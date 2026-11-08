//! Extracting archives made to attack extractors: names that climb out of
//! the destination, the same path twice, links in the archive and on disk,
//! files already there, archive bombs past the limits or sharing their
//! data, and data that fails its check. Each must stop with its reason,
//! and leave nothing outside the destination. Then the options, the time
//! limit, cancelling and progress.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "extract_support/mod.rs"]
mod support;

use std::io::Cursor;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use hivepack::extract::{
    Cancel, ErrorKind, Limits, LinkOutside, Links, NameError, Names, OnLinksOutside, OnRefused,
    Options, Origin, Progress, extract_zip,
};
use hivepack::zip::{Archive, BufferSource, Flags, OpenFlags, em};
use support::{
    Entry, MTIME, Scratch, central_entries, extract, limits, listing, options, patch_size,
    required, testdata, zip,
};

#[test]
fn extracts_files_and_directories() {
    let scratch = Scratch::new();
    let data = zip(&[
        Entry::File(b"a.txt", b"hello"),
        Entry::Dir(b"dir/"),
        Entry::File(b"dir/b.txt", b"world"),
        Entry::Stored("dir/sub/naïve.bin".as_bytes(), &[0, 1, 2, 3]),
        Entry::File(b"empty", b""),
    ]);
    let summary = extract(&data, &scratch.out(), &portable()).unwrap();
    assert_eq!(
        (summary.files, summary.directories, summary.bytes),
        (4, 1, 14)
    );
    assert_eq!(
        listing(&scratch.out()),
        [
            "a.txt",
            "dir/",
            "dir/b.txt",
            "dir/sub/",
            "dir/sub/naïve.bin",
            "empty"
        ]
    );
    assert_eq!(
        std::fs::read(scratch.out().join("a.txt")).unwrap(),
        b"hello"
    );
    assert_eq!(
        std::fs::read(scratch.out().join("dir/sub/naïve.bin")).unwrap(),
        [0, 1, 2, 3]
    );
    let modified = std::fs::metadata(scratch.out().join("dir/b.txt"))
        .unwrap()
        .modified()
        .unwrap();
    assert_eq!(
        modified
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        MTIME as u64
    );
}

#[cfg(unix)]
#[test]
fn unix_permissions_are_masked() {
    use std::os::unix::fs::PermissionsExt;
    let scratch = Scratch::new();
    let data = zip(&[
        Entry::Mode(b"setuid", b"x", 0o104_777),
        Entry::Mode(b"private", b"x", 0o100_600),
        Entry::Mode(b"read-only", b"x", 0o100_444),
        Entry::Mode(b"script", b"x", 0o100_775),
    ]);
    extract(&data, &scratch.out(), &portable()).unwrap();
    for (name, mode) in [
        ("setuid", 0o755),
        ("private", 0o600),
        ("read-only", 0o644),
        ("script", 0o755),
    ] {
        let metadata = std::fs::metadata(scratch.out().join(name)).unwrap();
        assert_eq!(metadata.permissions().mode() & 0o7777, mode, "{name}");
    }
}

#[test]
fn refused_names_write_nothing() {
    let cases: &[(&[u8], NameError)] = &[
        (b"../evil", NameError::Dot),
        (b"a/../../evil", NameError::Dot),
        (b"/tmp/evil", NameError::Absolute),
        // Windows' separator: it climbs, before it is a backslash.
        (b"a\\..\\evil", NameError::Dot),
        (b"a\\evil", NameError::Backslash),
        (b"C:evil", NameError::Colon),
        (b"a.txt:hidden", NameError::Colon),
        (b"CON", NameError::Device),
        (b"dir/nul.txt", NameError::Device),
        (b"evil./x", NameError::TrailingSpaceOrDot),
        (b"a//b", NameError::Empty),
        (b"a\x01b", NameError::Control),
    ];
    for &(name, reason) in cases {
        let scratch = Scratch::new();
        let data = zip(&[Entry::File(b"good.txt", b"ok"), Entry::File(name, b"evil")]);
        let shown = String::from_utf8_lossy(name);
        let Err(error) = extract(&data, &scratch.out(), &portable()) else {
            panic!("{shown:?} extracted: {:?}", listing(&scratch.out()));
        };
        assert!(
            matches!(error.kind, ErrorKind::Name(r) if r == reason),
            "{shown}: {error}"
        );
        assert_eq!(error.index, Some(1), "{shown}");
        assert_eq!(error.name.as_deref(), Some(name), "{shown}");
        // Checked before anything is written, the destination too.
        assert!(listing(scratch.path()).is_empty(), "{shown}");
    }
}

#[test]
fn the_same_path_twice_is_refused() {
    let cases: &[&[Entry<'_>]] = &[
        &[Entry::File(b"A.txt", b"1"), Entry::File(b"a.txt", b"2")],
        &[Entry::File(b"dir/x", b"1"), Entry::File(b"DIR/y", b"2")],
        &[Entry::File(b"a", b"1"), Entry::File(b"a/b", b"2")],
        &[Entry::File(b"a/b", b"1"), Entry::File(b"a", b"2")],
        &[Entry::Dir(b"d/"), Entry::File(b"D", b"2")],
        &[
            Entry::File("É".as_bytes(), b"1"),
            Entry::File("é".as_bytes(), b"2"),
        ],
    ];
    for entries in cases {
        let scratch = Scratch::new();
        let error = extract(&zip(entries), &scratch.out(), &portable()).unwrap_err();
        assert!(
            matches!(error.kind, ErrorKind::Duplicate { first: 0 }),
            "{error}"
        );
        assert!(listing(&scratch.out()).is_empty());
    }
    // A directory entry after the files in it is fine.
    let scratch = Scratch::new();
    let data = zip(&[Entry::File(b"d/x", b"1"), Entry::Dir(b"d/")]);
    extract(&data, &scratch.out(), &portable()).unwrap();
    assert_eq!(listing(&scratch.out()), ["d/", "d/x"]);
}

/// One name written two ways, which macOS or a case-insensitive file
/// system takes for one, is the same path.
#[test]
fn one_name_written_two_ways_is_the_same_path() {
    for (a, b) in [
        ("caf\u{e9}.txt", "cafe\u{301}.txt"),
        ("\u{212a}.txt", "k.txt"),
        ("\u{3c3}.txt", "\u{3c2}.txt"),
        // Full case folding, as macOS folds names: it takes `fi` for the
        // ligature, and refuses the second.
        ("stra\u{df}e.txt", "strasse.txt"),
        ("\u{fb01}", "fi"),
        // A directory one way, then on the way of another entry.
        ("caf\u{e9}/a", "cafe\u{301}/b"),
    ] {
        let scratch = Scratch::new();
        let data = zip(&[
            Entry::File(a.as_bytes(), b"1"),
            Entry::File(b.as_bytes(), b"2"),
        ]);
        let error = extract(&data, &scratch.out(), &portable()).unwrap_err();
        assert!(
            matches!(error.kind, ErrorKind::Duplicate { first: 0 }),
            "{a:?} {b:?}: {error}"
        );
        assert!(!scratch.out().exists());
    }
    assert_eq!(hivepack::extract::UNICODE_VERSION, (18, 0, 0));
}

#[test]
fn links_are_not_created() {
    let scratch = Scratch::new();
    let data = zip(&[Entry::Mode(b"x", b"/etc/passwd", 0o120_777)]);
    let error = extract(&data, &scratch.out(), &portable()).unwrap_err();
    assert!(matches!(error.kind, ErrorKind::Link), "{error}");
    assert!(listing(&scratch.out()).is_empty());
}

/// A FIFO or a device in a ZIP archive is a mode with data, as Info-ZIP's
/// zip writes what it reads from a pipe: written as a file.
#[test]
fn special_files_are_written_as_files() {
    for mode in [0o010_644, 0o020_644, 0o060_644, 0o140_644] {
        let scratch = Scratch::new();
        let data = zip(&[Entry::Mode(b"-", b"from a pipe", mode)]);
        extract(&data, &scratch.out(), &portable()).unwrap();
        let path = scratch.out().join("-");
        assert!(
            std::fs::symlink_metadata(&path).unwrap().is_file(),
            "{mode:o}"
        );
        assert_eq!(std::fs::read(&path).unwrap(), b"from a pipe");
    }
}

/// A link already in the destination is not followed, as a directory on
/// the way or as the file itself.
#[cfg(unix)]
#[test]
fn links_in_the_destination_are_not_followed() {
    let scratch = Scratch::new();
    let outside = scratch.path().join("outside");
    std::fs::create_dir(&outside).unwrap();
    std::fs::write(outside.join("victim"), b"untouched").unwrap();
    std::fs::create_dir(scratch.out()).unwrap();
    std::os::unix::fs::symlink(&outside, scratch.out().join("link")).unwrap();
    std::os::unix::fs::symlink(outside.join("victim"), scratch.out().join("victim")).unwrap();

    let data = zip(&[Entry::File(b"link/evil", b"evil")]);
    let error = extract(&data, &scratch.out(), &portable()).unwrap_err();
    assert!(matches!(error.kind, ErrorKind::NotADirectory), "{error}");

    let data = zip(&[Entry::File(b"victim", b"evil")]);
    let error = extract(&data, &scratch.out(), &portable()).unwrap_err();
    assert!(matches!(error.kind, ErrorKind::Exists), "{error}");

    assert_eq!(listing(&outside), ["victim"]);
    assert_eq!(std::fs::read(outside.join("victim")).unwrap(), b"untouched");
}

#[test]
fn nothing_is_overwritten() {
    let scratch = Scratch::new();
    std::fs::create_dir_all(scratch.out().join("dir")).unwrap();
    std::fs::write(scratch.out().join("dir/a.txt"), b"mine").unwrap();
    let data = zip(&[Entry::File(b"dir/a.txt", b"theirs")]);
    let error = extract(&data, &scratch.out(), &portable()).unwrap_err();
    assert!(matches!(error.kind, ErrorKind::Exists), "{error}");
    assert_eq!(
        std::fs::read(scratch.out().join("dir/a.txt")).unwrap(),
        b"mine"
    );
    // A file where a directory is to be.
    let data = zip(&[Entry::File(b"dir/a.txt/b", b"theirs")]);
    let error = extract(&data, &scratch.out(), &portable()).unwrap_err();
    assert!(matches!(error.kind, ErrorKind::NotADirectory), "{error}");
    // A directory where a file is to be, which Windows reports as access
    // denied.
    let data = zip(&[Entry::File(b"dir", b"theirs")]);
    let error = extract(&data, &scratch.out(), &portable()).unwrap_err();
    assert!(matches!(error.kind, ErrorKind::Exists), "{error}");
}

#[test]
fn limits_stop_archive_bombs() {
    let three = zip(&[
        Entry::File(b"a", &[1; 10]),
        Entry::File(b"b", &[2; 10]),
        Entry::File(b"c", &[3; 10]),
    ]);
    type Expected = fn(&ErrorKind) -> bool;
    let cases: Vec<(Options, Expected)> = vec![
        (limits(|l| l.max_entries = 2), |k| {
            matches!(k, ErrorKind::TooManyEntries)
        }),
        (limits(|l| l.max_entry_size = 9), |k| {
            matches!(k, ErrorKind::EntryTooLarge)
        }),
        (limits(|l| l.max_total_size = 25), |k| {
            matches!(k, ErrorKind::TotalTooLarge)
        }),
    ];
    for (options, expected) in cases {
        let scratch = Scratch::new();
        let error = extract(&three, &scratch.out(), &options).unwrap_err();
        assert!(expected(&error.kind), "{error}");
        // What the archive says is checked before anything is written.
        assert!(listing(&scratch.out()).is_empty(), "{error}");
    }

    // Two MiB of zeros, deflated to about two KiB.
    let zeros = vec![0u8; 2 << 20];
    let data = zip(&[Entry::File(b"ok", b"fine"), Entry::File(b"bomb", &zeros)]);
    let scratch = Scratch::new();
    let options = limits(|l| l.max_ratio = 100);
    let error = extract(&data, &scratch.out(), &options).unwrap_err();
    assert!(matches!(error.kind, ErrorKind::Ratio), "{error}");
    // The file cut off is removed; the one before stays.
    assert_eq!(listing(&scratch.out()), ["ok"]);
    let scratch = Scratch::new();
    extract(&data, &scratch.out(), &portable()).unwrap();
}

/// Two central directory entries for the same data, as Fifield's
/// overlapping bombs have: refused before anything is written.
#[test]
fn entries_that_share_data_are_refused() {
    let data = zip(&[Entry::File(b"a", &[7; 1000])]);
    let (start, size) = central_entries(&data)[0];
    let mut copy = data[start..start + size].to_vec();
    // The same entry, named "b".
    let name = 46;
    copy[name] = b'b';
    let eocd = data.len() - 22;
    let mut bomb = data[..eocd].to_vec();
    bomb.extend_from_slice(&copy);
    let mut end = data[eocd..].to_vec();
    for o in [8, 10] {
        end[o] = 2;
    }
    let cd_size = u32::from_le_bytes(end[12..16].try_into().unwrap()) + size as u32;
    end[12..16].copy_from_slice(&cd_size.to_le_bytes());
    bomb.extend_from_slice(&end);

    let scratch = Scratch::new();
    // Not with ZIP_CHECKCONS, which refuses the local header named "a" for
    // the entry "b" already.
    let archive = Archive::open(bomb.as_slice(), OpenFlags(0)).unwrap();
    let error = extract_zip(&archive, &scratch.out(), &portable()).unwrap_err();
    assert!(
        matches!(error.kind, ErrorKind::Overlap { other: 0 }),
        "{error}"
    );
    assert_eq!(error.index, Some(1));
    assert!(listing(&scratch.out()).is_empty());
}

#[test]
fn data_that_fails_is_removed() {
    // A byte of stored data changed: its CRC-32 fails.
    let mut data = zip(&[
        Entry::File(b"first", b"fine"),
        Entry::Stored(b"second", b"0123456789"),
    ]);
    let at = data.windows(10).position(|w| w == b"0123456789").unwrap();
    data[at + 4] ^= 1;
    let scratch = Scratch::new();
    let error = extract(&data, &scratch.out(), &portable()).unwrap_err();
    assert!(
        matches!(&error.kind, ErrorKind::Archive(e) if e.code() == hivepack::zip::ErrorCode::Crc),
        "{error}"
    );
    assert_eq!(listing(&scratch.out()), ["first"]);

    // More data than the archive says: cut off where it passes the size.
    let mut data = zip(&[Entry::File(b"big", &[5; 100_000])]);
    patch_size(&mut data, 0, 1000);
    let scratch = Scratch::new();
    let error = extract(&data, &scratch.out(), &portable()).unwrap_err();
    assert!(matches!(error.kind, ErrorKind::SizeMismatch), "{error}");
    assert!(listing(&scratch.out()).is_empty());
}

#[test]
fn encrypted_entries_need_their_password() {
    let mut za = Archive::open(&[][..], OpenFlags(0)).unwrap();
    za.set_random_source(Some(std::sync::Arc::new(|buffer: &mut [u8]| {
        buffer.fill(7);
        Ok(())
    })));
    for (name, method) in [
        (&b"aes"[..], em::AES_256),
        (&b"zipcrypto"[..], em::TRAD_PKWARE),
    ] {
        let i = za
            .file_add(
                name,
                BufferSource::with_mtime(&b"secret"[..], MTIME),
                Flags::NONE,
            )
            .unwrap();
        za.file_set_encryption(i, method, Some(b"password"))
            .unwrap();
    }
    let mut out = Cursor::new(Vec::new());
    za.close_to(&mut out).unwrap();
    let data = out.into_inner();

    let scratch = Scratch::new();
    let error = extract(&data, &scratch.out(), &portable()).unwrap_err();
    assert!(
        matches!(&error.kind, ErrorKind::Archive(e) if e.code() == hivepack::zip::ErrorCode::NoPasswd),
        "{error}"
    );
    assert!(listing(&scratch.out()).is_empty());

    let scratch = Scratch::new();
    let mut options = portable();
    options.password = Some(b"password".to_vec());
    extract(&data, &scratch.out(), &options).unwrap();
    assert_eq!(std::fs::read(scratch.out().join("aes")).unwrap(), b"secret");
    assert_eq!(
        std::fs::read(scratch.out().join("zipcrypto")).unwrap(),
        b"secret"
    );
}

/// Links whose target stays inside are created, last; the others are
/// refused, here skipped.
#[cfg(unix)]
#[test]
fn links_inside_the_destination_are_created() {
    let scratch = Scratch::new();
    let data = zip(&[
        Entry::Dir(b"lib/"),
        Entry::Mode(b"lib/libfoo.so", b"libfoo.so.1", 0o120_777),
        Entry::File(b"lib/libfoo.so.1", b"elf"),
        Entry::Mode(b"up", b"lib/../lib/libfoo.so.1", 0o120_777),
        Entry::Mode(b"to-dir", b"lib", 0o120_777),
        Entry::Mode(b"escape", b"../outside", 0o120_777),
        Entry::Mode(b"absolute", b"/etc/passwd", 0o120_777),
        Entry::Mode(b"through", b"to-dir/libfoo.so.1", 0o120_777),
    ]);
    let options = options(|o| {
        o.links = Links::Inside;
        o.on_refused = OnRefused::Skip;
    });
    let summary = extract(&data, &scratch.out(), &options).unwrap();
    assert_eq!((summary.files, summary.links), (1, 3));
    let reasons: Vec<_> = summary
        .skipped
        .iter()
        .map(|e| (e.index, format!("{:?}", e.kind)))
        .collect();
    assert_eq!(
        reasons,
        [
            (Some(5), "LinkTarget(Dot)".to_string()),
            (Some(6), "LinkTarget(Absolute)".to_string()),
            (Some(7), "LinkChain { other: 4 }".to_string()),
        ]
    );
    let out = scratch.out();
    assert_eq!(
        std::fs::read_link(out.join("lib/libfoo.so")).unwrap(),
        Path::new("libfoo.so.1")
    );
    assert_eq!(std::fs::read(out.join("up")).unwrap(), b"elf");
    assert_eq!(
        std::fs::read(out.join("to-dir/libfoo.so.1")).unwrap(),
        b"elf"
    );
    assert_eq!(listing(scratch.path()).len(), listing(&out).len() + 1);

    // Stopping, the default: before anything is written.
    let scratch = Scratch::new();
    let options = self::options(|o| o.links = Links::Inside);
    let error = extract(&data, &scratch.out(), &options).unwrap_err();
    assert!(
        matches!(error.kind, ErrorKind::LinkTarget(NameError::Dot)),
        "{error}"
    );
    assert!(listing(scratch.path()).is_empty());
}

/// With `Links::Any`, every link is created as the archive has it, last; a
/// path under a link is still the link's, and a target that is no path is
/// still refused.
#[cfg(unix)]
#[test]
fn links_anywhere_are_created_with_links_any() {
    let scratch = Scratch::new();
    let data = zip(&[
        Entry::Dir(b"lib/"),
        Entry::File(b"lib/libfoo.so.1", b"elf"),
        Entry::Mode(b"to-dir", b"lib", 0o120_777),
        Entry::Mode(b"escape", b"../outside", 0o120_777),
        Entry::Mode(b"absolute", b"/etc/passwd", 0o120_777),
        Entry::Mode(b"through", b"to-dir/libfoo.so.1", 0o120_777),
    ]);
    let summary = extract(&data, &scratch.out(), &options(|o| o.links = Links::Any)).unwrap();
    assert_eq!((summary.files, summary.links), (1, 4));
    assert!(summary.skipped.is_empty());
    let out = scratch.out();
    for (link, target) in [
        ("to-dir", "lib"),
        ("escape", "../outside"),
        ("absolute", "/etc/passwd"),
        ("through", "to-dir/libfoo.so.1"),
    ] {
        assert_eq!(
            std::fs::read_link(out.join(link)).unwrap(),
            Path::new(target)
        );
    }
    // Nothing beside the destination.
    assert_eq!(listing(scratch.path()).len(), listing(&out).len() + 1);

    // A file under a link that leads out: the same path as the link.
    let scratch = Scratch::new();
    let data = zip(&[
        Entry::Mode(b"out", b"/tmp", 0o120_777),
        Entry::File(b"out/x", b"through"),
    ]);
    let error = extract(&data, &scratch.out(), &options(|o| o.links = Links::Any)).unwrap_err();
    assert!(matches!(error.kind, ErrorKind::Duplicate { .. }), "{error}");
    assert!(listing(scratch.path()).is_empty());

    // An empty target.
    let scratch = Scratch::new();
    let data = zip(&[Entry::Mode(b"empty", b"", 0o120_777)]);
    let error = extract(&data, &scratch.out(), &options(|o| o.links = Links::Any)).unwrap_err();
    assert!(
        matches!(error.kind, ErrorKind::LinkTarget(NameError::Empty)),
        "{error}"
    );
}

/// With `Links::Inside`, the links that lead outside are asked about once,
/// with their targets, before anything is written; as answered, they stop it,
/// are left out, or are created.
#[cfg(unix)]
#[test]
fn links_outside_are_asked_about_once() {
    let data = zip(&[
        Entry::Dir(b"lib/"),
        Entry::File(b"lib/libfoo.so.1", b"elf"),
        Entry::Mode(b"inside", b"lib/libfoo.so.1", 0o120_777),
        Entry::Mode(b"escape", b"../outside", 0o120_777),
        Entry::Mode(b"absolute", b"/etc/passwd", 0o120_777),
        Entry::Mode(b"to-dir", b"lib", 0o120_777),
        Entry::Mode(b"through", b"to-dir/libfoo.so.1", 0o120_777),
    ]);
    // Each question: the links told, by index, with their targets.
    type Told = Arc<Mutex<Vec<Vec<(u64, String)>>>>;
    let asking = |answer: OnLinksOutside, told: Told| {
        options(move |o| {
            o.links = Links::Inside;
            o.on_links_outside = Some(Arc::new(move |links: &[LinkOutside]| {
                told.lock().unwrap().push(
                    links
                        .iter()
                        .map(|l| (l.error.index.unwrap(), l.target.clone()))
                        .collect(),
                );
                answer
            }));
        })
    };
    let expected = vec![vec![
        (3, "../outside".to_string()),
        (4, "/etc/passwd".to_string()),
        (6, "to-dir/libfoo.so.1".to_string()),
    ]];

    // Stop: nothing written.
    let scratch = Scratch::new();
    let told = Arc::new(Mutex::new(Vec::new()));
    let error = extract(
        &data,
        &scratch.out(),
        &asking(OnLinksOutside::Stop, told.clone()),
    )
    .unwrap_err();
    assert!(
        matches!(error.kind, ErrorKind::LinkTarget(NameError::Dot)),
        "{error}"
    );
    assert_eq!(*told.lock().unwrap(), expected);
    assert!(listing(scratch.path()).is_empty());

    // Skip: left out, the rest created.
    let scratch = Scratch::new();
    let told = Arc::new(Mutex::new(Vec::new()));
    let summary = extract(
        &data,
        &scratch.out(),
        &asking(OnLinksOutside::Skip, told.clone()),
    )
    .unwrap();
    assert_eq!(*told.lock().unwrap(), expected);
    assert_eq!((summary.files, summary.links), (1, 2));
    let skipped: Vec<_> = summary.skipped.iter().map(|e| e.index).collect();
    assert_eq!(skipped, [Some(3), Some(4), Some(6)]);
    assert!(scratch.out().join("absolute").symlink_metadata().is_err());

    // Create: every one, as the archive has it.
    let scratch = Scratch::new();
    let told = Arc::new(Mutex::new(Vec::new()));
    let summary = extract(
        &data,
        &scratch.out(),
        &asking(OnLinksOutside::Create, told.clone()),
    )
    .unwrap();
    assert_eq!(*told.lock().unwrap(), expected);
    assert_eq!((summary.files, summary.links), (1, 5));
    assert!(summary.skipped.is_empty());
    assert_eq!(
        std::fs::read_link(scratch.out().join("absolute")).unwrap(),
        Path::new("/etc/passwd")
    );
    assert_eq!(
        listing(scratch.path()).len(),
        listing(&scratch.out()).len() + 1
    );

    // None leads outside: nothing is asked.
    let scratch = Scratch::new();
    let told = Arc::new(Mutex::new(Vec::new()));
    let inside = zip(&[Entry::File(b"f", b"x"), Entry::Mode(b"l", b"f", 0o120_777)]);
    extract(
        &inside,
        &scratch.out(),
        &asking(OnLinksOutside::Stop, told.clone()),
    )
    .unwrap();
    assert!(told.lock().unwrap().is_empty());
}

#[test]
fn links_can_be_written_as_files() {
    let scratch = Scratch::new();
    let data = zip(&[Entry::Mode(b"link", b"../../etc/passwd", 0o120_777)]);
    let options = options(|o| o.links = Links::AsFile);
    extract(&data, &scratch.out(), &options).unwrap();
    assert_eq!(
        std::fs::read(scratch.out().join("link")).unwrap(),
        b"../../etc/passwd"
    );
    assert!(
        !std::fs::symlink_metadata(scratch.out().join("link"))
            .unwrap()
            .is_symlink()
    );
}

#[test]
fn names_can_be_cleaned_up() {
    let scratch = Scratch::new();
    let data = zip(&[
        Entry::File(b"/etc/passwd", b"1"),
        Entry::File(b"../../up", b"2"),
        Entry::File(b"C:\\win\\..\\x.txt", b"3"),
        Entry::File(b"a/./b//c", b"4"),
    ]);
    let options = options(|o| {
        o.names = Names::Sanitize;
        o.backslash_separator = true;
    });
    extract(&data, &scratch.out(), &options).unwrap();
    assert_eq!(
        listing(&scratch.out()),
        [
            "a/",
            "a/b/",
            "a/b/c",
            "etc/",
            "etc/passwd",
            "up",
            "win/",
            "win/x.txt"
        ]
    );

    // A backslash for a separator, nothing cleaned up.
    let scratch = Scratch::new();
    let data = zip(&[Entry::File(b"dir\\file.txt", b"x")]);
    let options = self::options(|o| o.backslash_separator = true);
    extract(&data, &scratch.out(), &options).unwrap();
    assert_eq!(listing(&scratch.out()), ["dir/", "dir/file.txt"]);
}

#[test]
fn refused_entries_can_be_skipped() {
    let scratch = Scratch::new();
    let data = zip(&[
        Entry::File(b"good.txt", b"ok"),
        Entry::File(b"../evil", b"x"),
        Entry::File(b"CON", b"x"),
        Entry::File(b"GOOD.txt", b"x"),
        Entry::Mode(b"link", b"good.txt", 0o120_777),
        Entry::File(b"also-good", b"ok"),
    ]);
    let options = options(|o| o.on_refused = OnRefused::Skip);
    let summary = extract(&data, &scratch.out(), &options).unwrap();
    assert_eq!(listing(&scratch.out()), ["also-good", "good.txt"]);
    let skipped: Vec<_> = summary.skipped.iter().map(|e| e.index.unwrap()).collect();
    assert_eq!(skipped, [1, 2, 3, 4]);
    assert!(matches!(
        summary.skipped[2].kind,
        ErrorKind::Duplicate { first: 0 }
    ));

    // The limits still stop it.
    let scratch = Scratch::new();
    let options = self::options(|o| {
        o.on_refused = OnRefused::Skip;
        o.limits.max_entries = 3;
    });
    let error = extract(&data, &scratch.out(), &options).unwrap_err();
    assert!(matches!(error.kind, ErrorKind::TooManyEntries), "{error}");
}

#[test]
fn files_can_be_overwritten() {
    let scratch = Scratch::new();
    std::fs::create_dir_all(scratch.out().join("dir/sub")).unwrap();
    std::fs::write(scratch.out().join("a.txt"), b"mine, and longer").unwrap();
    let options = options(|o| o.overwrite = true);
    extract(
        &zip(&[Entry::File(b"a.txt", b"theirs")]),
        &scratch.out(),
        &options,
    )
    .unwrap();
    assert_eq!(
        std::fs::read(scratch.out().join("a.txt")).unwrap(),
        b"theirs"
    );
    // Not a directory.
    let error = extract(
        &zip(&[Entry::File(b"dir/sub", b"x")]),
        &scratch.out(),
        &options,
    )
    .unwrap_err();
    assert!(matches!(error.kind, ErrorKind::Exists), "{error}");
}

/// Not a link, even with `overwrite`: the file it points to is untouched.
#[cfg(unix)]
#[test]
fn links_are_not_overwritten() {
    let scratch = Scratch::new();
    std::fs::create_dir(scratch.out()).unwrap();
    let victim = scratch.path().join("victim");
    std::fs::write(&victim, b"untouched").unwrap();
    std::os::unix::fs::symlink(&victim, scratch.out().join("a.txt")).unwrap();
    let options = options(|o| o.overwrite = true);
    let error = extract(
        &zip(&[Entry::File(b"a.txt", b"theirs")]),
        &scratch.out(),
        &options,
    )
    .unwrap_err();
    assert!(matches!(error.kind, ErrorKind::Exists), "{error}");
    assert_eq!(std::fs::read(&victim).unwrap(), b"untouched");
}

#[cfg(unix)]
#[test]
fn permissions_can_be_kept_or_left_to_the_system() {
    use hivepack::extract::Permissions;
    use std::os::unix::fs::PermissionsExt;
    let data = zip(&[Entry::Mode(b"x", b"x", 0o106_775)]);
    let mode = |permissions| {
        let scratch = Scratch::new();
        let options = options(|o| o.permissions = permissions);
        extract(&data, &scratch.out(), &options).unwrap();
        std::fs::metadata(scratch.out().join("x"))
            .unwrap()
            .permissions()
            .mode()
            & 0o7777
    };
    assert_eq!(mode(Permissions::Masked), 0o755);
    assert_eq!(mode(Permissions::Preserve), 0o775);
    // The system's: no setuid or setgid bit either way.
    assert_eq!(mode(Permissions::Ignore) & 0o7000, 0);
}

#[test]
fn directories_get_their_time() {
    let scratch = Scratch::new();
    let data = zip(&[
        Entry::DirAt(b"dir/"),
        Entry::File(b"dir/inner/file", b"x"),
        Entry::DirAt(b"dir/inner/"),
    ]);
    extract(&data, &scratch.out(), &portable()).unwrap();
    for dir in ["dir", "dir/inner"] {
        let modified = std::fs::metadata(scratch.out().join(dir))
            .unwrap()
            .modified()
            .unwrap();
        assert_eq!(
            modified
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            MTIME as u64,
            "{dir}"
        );
    }
}

#[test]
fn a_time_limit_stops_the_extraction() {
    let scratch = Scratch::new();
    let data = zip(&[Entry::File(b"a.txt", b"a")]);
    let error = extract(
        &data,
        &scratch.out(),
        &options(|o| o.time_limit = Some(Duration::ZERO)),
    )
    .unwrap_err();
    assert!(matches!(error.kind, ErrorKind::TimeLimit), "{error}");
    assert!(!scratch.out().exists());
    // A limit too far to count is none.
    let summary = extract(
        &data,
        &scratch.out(),
        &options(|o| o.time_limit = Some(Duration::MAX)),
    )
    .unwrap();
    assert_eq!(summary.files, 1);
}

#[test]
fn cancelling_stops_the_extraction() {
    // Options, with their token and progress function, go to another
    // thread, and the token is cancelled from any.
    fn send_sync<T: Send + Sync>() {}
    send_sync::<Options>();
    send_sync::<Cancel>();

    let scratch = Scratch::new();
    let big: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
    let data = zip(&[Entry::File(b"a", b"a"), Entry::File(b"big", &big)]);

    let cancel = Cancel::new();
    cancel.cancel();
    let error = extract(
        &data,
        &scratch.out(),
        &options(|o| o.cancel = Some(cancel.clone())),
    )
    .unwrap_err();
    assert!(matches!(error.kind, ErrorKind::Cancelled), "{error}");
    assert_eq!(error.index, None);
    assert!(!scratch.out().exists());

    // Cancelled once the second file has written a piece: it is removed,
    // and the first stays.
    let cancel = Cancel::new();
    let token = cancel.clone();
    let error = extract(
        &data,
        &scratch.out(),
        &options(|o| {
            o.cancel = Some(cancel);
            o.progress = Some(Arc::new(move |progress: &Progress| {
                if progress.entries == 1 && progress.bytes > 1 {
                    token.cancel();
                }
            }));
        }),
    )
    .unwrap_err();
    assert!(matches!(error.kind, ErrorKind::Cancelled), "{error}");
    assert_eq!(error.index, Some(1));
    assert_eq!(listing(&scratch.out()), ["a"]);
}

#[test]
fn progress_counts_what_is_written() {
    let scratch = Scratch::new();
    let big: Vec<u8> = (0..100_000u32).map(|i| (i % 251) as u8).collect();
    let data = zip(&[
        Entry::Dir(b"d/"),
        Entry::File(b"d/big", &big),
        Entry::File(b"b", b"abc"),
    ]);
    let seen = Arc::new(Mutex::new(Vec::new()));
    let record = Arc::clone(&seen);
    let summary = extract(
        &data,
        &scratch.out(),
        &options(|o| {
            o.progress = Some(Arc::new(move |progress: &Progress| {
                record.lock().unwrap().push(*progress);
            }));
        }),
    )
    .unwrap();
    let seen = seen.lock().unwrap();
    let total_bytes = big.len() as u64 + 3;
    // Told the totals before anything is written, then each piece and
    // each entry, never going back.
    let first = seen.first().unwrap();
    assert_eq!((first.entries, first.bytes), (0, 0));
    for progress in seen.iter() {
        assert_eq!(
            (progress.total_entries, progress.total_bytes),
            (3, total_bytes)
        );
    }
    for pair in seen.windows(2) {
        assert!(pair[0].entries <= pair[1].entries && pair[0].bytes <= pair[1].bytes);
    }
    // Pieces of 64 KiB at most: two for the big file, one for the small.
    let pieces: Vec<u64> = seen
        .windows(2)
        .map(|pair| pair[1].bytes - pair[0].bytes)
        .filter(|&n| n > 0)
        .collect();
    assert!(
        pieces.len() >= 3 && pieces.iter().all(|&n| n <= 64 * 1024),
        "{pieces:?}"
    );
    let last = seen.last().unwrap();
    assert_eq!((last.entries, last.bytes), (3, total_bytes));
    assert_eq!(summary.bytes, total_bytes);
}

/// A mark this system cannot carry stops the extraction before anything is
/// written: an extraction that drops it would hide where files came from.
#[test]
fn a_mark_this_system_cannot_carry_is_refused() {
    let scratch = Scratch::new();
    let data = zip(&[Entry::File(b"a.txt", b"a")]);
    let foreign = if cfg!(windows) {
        Origin::Quarantine(b"0083;6720f5a0;Safari;".to_vec())
    } else {
        Origin::ZoneIdentifier(b"[ZoneTransfer]\r\nZoneId=3\r\n".to_vec())
    };
    let error = extract(
        &data,
        &scratch.out(),
        &options(|o| o.origin = Some(foreign)),
    )
    .unwrap_err();
    assert!(
        matches!(&error.kind, ErrorKind::Origin(e) if e.kind() == std::io::ErrorKind::Unsupported),
        "{error}"
    );
    assert!(!scratch.out().exists());
}

/// Linux and the other systems have no mark.
#[cfg(not(any(windows, target_os = "macos")))]
#[test]
fn other_systems_have_no_mark() {
    let scratch = Scratch::new();
    let path = scratch.path().join("a.zip");
    std::fs::write(&path, zip(&[Entry::File(b"a", b"1")])).unwrap();
    assert_eq!(Origin::of(&path).unwrap(), None);
}

/// The archive's Mark of the Web is carried to every file, as it is,
/// written from each file's handle. One file is named `a`, which beside a
/// colon would name drive A; the files keep their time.
#[cfg(windows)]
#[test]
fn the_mark_of_the_web_is_carried() {
    let scratch = Scratch::new();
    let path = scratch.path().join("download.zip");
    std::fs::write(
        &path,
        zip(&[Entry::File(b"a", b"1"), Entry::File(b"d/b.txt", b"2")]),
    )
    .unwrap();
    assert_eq!(Origin::of(&path).unwrap(), None);
    let mark = b"[ZoneTransfer]\r\nZoneId=3\r\nHostUrl=https://example.com/download.zip\r\n";
    std::fs::write(format!("{}:Zone.Identifier", path.display()), mark).unwrap();
    let origin = Origin::of(&path).unwrap().unwrap();
    assert_eq!(origin, Origin::ZoneIdentifier(mark.to_vec()));

    let data = std::fs::read(&path).unwrap();
    let summary = extract(&data, &scratch.out(), &options(|o| o.origin = Some(origin))).unwrap();
    assert_eq!(summary.files, 2);
    for file in ["a", "d/b.txt"] {
        let file = scratch.out().join(file);
        let stream = format!("{}:Zone.Identifier", file.display());
        assert_eq!(std::fs::read(&stream).unwrap(), mark, "{stream}");
        let modified = std::fs::metadata(&file).unwrap().modified().unwrap();
        assert_eq!(
            modified
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            MTIME as u64
        );
    }
}

/// The archive's quarantine is carried to every file, and to every
/// directory created, as an app is one, as it is.
#[cfg(target_os = "macos")]
#[test]
fn the_quarantine_is_carried() {
    const QUARANTINE: &str = "com.apple.quarantine";
    fn quarantine(path: &Path) -> Option<Vec<u8>> {
        let mut value = Vec::with_capacity(1024);
        rustix::fs::getxattr(path, QUARANTINE, rustix::buffer::spare_capacity(&mut value))
            .ok()
            .map(|_| value)
    }
    let scratch = Scratch::new();
    let path = scratch.path().join("download.zip");
    std::fs::write(
        &path,
        zip(&[
            Entry::File(b"a", b"1"),
            Entry::Dir(b"Some.app/"),
            Entry::File(b"Some.app/Contents/MacOS/some", b"2"),
        ]),
    )
    .unwrap();
    assert_eq!(Origin::of(&path).unwrap(), None);
    let mark = b"0083;6720f5a0;Safari;3A2B1C0D-0000-4000-8000-000000000000";
    rustix::fs::setxattr(&path, QUARANTINE, mark, rustix::fs::XattrFlags::empty()).unwrap();
    let origin = Origin::of(&path).unwrap().unwrap();
    assert_eq!(origin, Origin::Quarantine(mark.to_vec()));

    let data = std::fs::read(&path).unwrap();
    extract(&data, &scratch.out(), &options(|o| o.origin = Some(origin))).unwrap();
    for item in [
        "a",
        "Some.app",
        "Some.app/Contents",
        "Some.app/Contents/MacOS",
        "Some.app/Contents/MacOS/some",
    ] {
        assert_eq!(
            quarantine(&scratch.out().join(item)).as_deref(),
            Some(&mark[..]),
            "{item}"
        );
    }
}

/// The archives of libzip's tests, where the libzip sources are fetched.
fn regress_archives() -> Vec<(String, Vec<u8>)> {
    let regress = testdata().join("libzip-1.12.1-source/libzip-1.12.1/regress");
    let mut files = Vec::new();
    for folder in [regress.clone(), regress.join("data")] {
        let Ok(dir) = std::fs::read_dir(&folder) else {
            continue;
        };
        for entry in dir {
            let path = entry.unwrap().path();
            let name = path.file_name().unwrap().to_string_lossy().into_owned();
            if path.is_file() && !name.ends_with(".test") {
                files.push((name, std::fs::read(&path).unwrap()));
            }
        }
    }
    files.sort();
    files
}

/// Every archive of libzip's tests that opens extracts, or stops with its
/// reason, and writes nothing outside the destination: a test of the rules
/// on archives made by others, and a measure of what they refuse.
#[test]
fn libzip_archives_extract_or_stop_cleanly() {
    let archives = regress_archives();
    if archives.is_empty() {
        assert!(
            !required("generated"),
            "libzip's archives are missing: run `python3 scripts/testdata.py fetch --group generated`"
        );
        eprintln!("skipping: libzip's archives are not fetched");
        return;
    }
    let mut outcomes = std::collections::BTreeMap::<String, Vec<String>>::new();
    let mut opened = 0;
    for (name, data) in &archives {
        let Ok(archive) = Archive::open(data.as_slice(), OpenFlags::CHECKCONS) else {
            continue;
        };
        opened += 1;
        let scratch = Scratch::new();
        std::fs::write(scratch.path().join("sentinel"), b"untouched").unwrap();
        let mut options = portable();
        options.password = Some(b"foofoofoo".to_vec());
        let outcome = match extract_zip(&archive, &scratch.out(), &options) {
            Ok(summary) => {
                let files = listing(&scratch.out())
                    .iter()
                    .filter(|path| !path.ends_with('/'))
                    .count();
                assert_eq!(files as u64, summary.files, "{name}");
                "extracted".to_string()
            }
            Err(error) => {
                let kind = format!("{:?}", error.kind);
                kind.split(['(', ' ', '{'])
                    .next()
                    .unwrap_or_default()
                    .to_string()
            }
        };
        let mut around = listing(scratch.path());
        around.retain(|path| !path.starts_with("out/") && path != "out/");
        assert_eq!(around, ["sentinel"], "{name}");
        outcomes.entry(outcome).or_default().push(name.clone());
    }
    eprintln!("{opened} of {} archives open", archives.len());
    for (outcome, names) in &outcomes {
        eprintln!("{outcome}: {} ({})", names.len(), names.join(" "));
    }
    assert!(opened > 100, "only {opened} archives open");
}

/// David Fifield's zip bombs, whose entries share one stream, stop before
/// anything is written: with the default limits, on the data they share
/// (zbsm, whose 5.5 GB pass the limits), on what they say of their sizes
/// (zblg) or on their number of entries (zbxl); and with those lifted, on
/// the data they share. A ratio of ten to one, checked only while writing,
/// is set throughout, so that a bomb let through stops within its first
/// entry rather than fill the disk: without the overlap check, zbsm writes
/// 5.5 GB under the default limits.
#[test]
fn fifield_zip_bombs_write_nothing() {
    let folder = testdata().join("fifield-zipbombs");
    if !folder.join("zbsm.zip").exists() {
        assert!(
            !required("core"),
            "Fifield's zip bombs are missing: run `python3 scripts/testdata.py fetch`"
        );
        eprintln!("skipping: Fifield's zip bombs are not fetched");
        return;
    }
    let bombs = [
        ("zbsm.zip", 250, "Overlap"),
        ("zblg.zip", 65_534, "TotalTooLarge"),
        ("zbxl.zip", 190_023, "TooManyEntries"),
    ];
    for (name, entries, stops_by_default) in bombs {
        let data = std::fs::read(folder.join(name)).unwrap();
        for flags in [OpenFlags::CHECKCONS, OpenFlags(0)] {
            let archive = match Archive::open(data.as_slice(), flags) {
                Ok(archive) => archive,
                Err(error) => {
                    eprintln!("{name}, {flags:?}: not opened: {error}");
                    continue;
                }
            };
            assert_eq!(archive.get_num_entries(Flags::NONE), entries, "{name}");
            let scratch = Scratch::new();
            let outcome = |options: &Options| {
                let error = extract_zip(&archive, &scratch.out(), options).unwrap_err();
                assert!(!scratch.out().exists(), "{name}: {error}");
                error.kind
            };
            let net = |limits: &mut Limits| {
                limits.max_ratio = 10;
                limits.ratio_threshold = 64 << 10;
            };
            let by_default = outcome(&limits(net));
            let lifted = outcome(&options(|o| {
                net(&mut o.limits);
                o.limits.max_entries = entries;
                o.limits.max_entry_size = u64::MAX;
                o.limits.max_total_size = u64::MAX;
                o.on_refused = OnRefused::Skip;
            }));
            assert!(
                format!("{by_default:?}").starts_with(stops_by_default),
                "{name}: {by_default}"
            );
            assert!(
                matches!(lifted, ErrorKind::Overlap { .. }),
                "{name}: {lifted}"
            );
        }
    }
}

/// ZipDiff's archives (`testdata/zipdiff`), which ZIP parsers read
/// differently, read from the one archive they are kept in.
fn zipdiff_archives() -> Vec<(String, Vec<u8>)> {
    let path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata/zipdiff/constructions.zip");
    let data = std::fs::read(path).unwrap();
    let za = Archive::open(data.as_slice(), OpenFlags::CHECKCONS).unwrap();
    (0..za.get_num_entries(Flags::NONE))
        .map(|i| {
            let name = String::from_utf8_lossy(za.get_name(i, Flags::NONE).unwrap()).into_owned();
            let mut file = za.fopen_index(i, Flags::NONE).unwrap();
            let mut bytes = Vec::new();
            std::io::Read::read_to_end(&mut file, &mut bytes).unwrap();
            (name, bytes)
        })
        .collect()
}

/// Every archive of ZipDiff that opens extracts, or stops with its reason,
/// and writes nothing outside the destination.
#[test]
fn zipdiff_archives_extract_or_stop_cleanly() {
    let archives = zipdiff_archives();
    assert_eq!(archives.len(), 5927);
    let mut outcomes = std::collections::BTreeMap::<(String, &str, String), usize>::new();
    for ((name, data), (flags, opened)) in archives.iter().flat_map(|archive| {
        [
            (OpenFlags::CHECKCONS, "checked"),
            (OpenFlags(0), "unchecked"),
        ]
        .map(|flags| (archive, flags))
    }) {
        let group = name.split('/').next().unwrap().to_string();
        let Ok(archive) = Archive::open(data.as_slice(), flags) else {
            *outcomes
                .entry((group, opened, "not opened".into()))
                .or_default() += 1;
            continue;
        };
        let scratch = Scratch::new();
        std::fs::write(scratch.path().join("sentinel"), b"untouched").unwrap();
        let outcome = match extract_zip(&archive, &scratch.out(), &portable()) {
            Ok(summary) => {
                let files = listing(&scratch.out())
                    .iter()
                    .filter(|path| !path.ends_with('/'))
                    .count();
                assert_eq!(files as u64, summary.files, "{name}");
                "extracted".to_string()
            }
            Err(error) => {
                let kind = format!("{:?}", error.kind);
                kind.split(['(', ' ', '{'])
                    .next()
                    .unwrap_or_default()
                    .to_string()
            }
        };
        let mut around = listing(scratch.path());
        around.retain(|path| !path.starts_with("out/") && path != "out/");
        assert_eq!(around, ["sentinel"], "{name}");
        *outcomes.entry((group, opened, outcome)).or_default() += 1;
    }
    let found: Vec<String> = outcomes
        .iter()
        .map(|((group, opened, outcome), n)| format!("{group} {opened} {outcome}: {n}"))
        .collect();
    // What each folder holds is in testdata/zipdiff/README.md, and what
    // these say in docs/extract.md.
    let expected = [
        "a1 checked not opened: 2",
        "a1 unchecked Archive: 1",
        "a1 unchecked extracted: 1",
        "a2 checked Archive: 8",
        "a2 checked SizeMismatch: 80",
        "a2 checked extracted: 273",
        "a2 checked not opened: 4248",
        "a2 unchecked Archive: 1152",
        "a2 unchecked SizeMismatch: 576",
        "a2 unchecked extracted: 2881",
        "a3 checked extracted: 2",
        "a3 checked not opened: 5",
        "a3 unchecked extracted: 7",
        "a4 checked Name: 1",
        "a4 checked extracted: 8",
        "a4 unchecked Name: 1",
        "a4 unchecked extracted: 8",
        "a5 checked extracted: 1",
        "a5 checked not opened: 2",
        "a5 unchecked Archive: 2",
        "a5 unchecked extracted: 1",
        "b1 checked not opened: 1",
        "b1 unchecked Duplicate: 1",
        "b2 checked Duplicate: 1",
        "b2 checked Name: 275",
        "b2 checked extracted: 685",
        "b2 checked not opened: 221",
        "b2 unchecked Duplicate: 154",
        "b2 unchecked Name: 343",
        "b2 unchecked extracted: 685",
        "b3 checked Name: 20",
        "b3 unchecked Name: 20",
        "b4 checked Duplicate: 1",
        "b4 unchecked Duplicate: 1",
        "c1 checked Overlap: 1",
        "c1 checked extracted: 4",
        "c1 checked not opened: 2",
        "c1 unchecked Overlap: 1",
        "c1 unchecked extracted: 5",
        "c1 unchecked not opened: 1",
        "c2 checked not opened: 3",
        "c2 unchecked extracted: 3",
        "c3 checked extracted: 1",
        "c3 checked not opened: 7",
        "c3 unchecked extracted: 2",
        "c3 unchecked not opened: 6",
        "c4 checked not opened: 1",
        "c4 unchecked extracted: 1",
        "c5 checked extracted: 7",
        "c5 checked not opened: 67",
        "c5 unchecked extracted: 9",
        "c5 unchecked not opened: 65",
    ];
    assert_eq!(found, expected);
}

/// The options of these tests: names checked by every system's rules, as Windows
/// and a case-insensitive file system have them, wherever the tests run.
fn portable() -> hivepack::extract::Options {
    let mut options = hivepack::extract::Options::default();
    options.name_rules = hivepack::extract::NameRules::Portable;
    options
}

/// What [`Options::on_written`](hivepack::extract::Options::on_written) is told,
/// by path and kind, sorted, as threads tell it in any order.
fn told_of(options: &mut Options) -> Arc<Mutex<Vec<(String, hivepack::extract::WrittenKind)>>> {
    let told = Arc::new(Mutex::new(Vec::new()));
    let into = Arc::clone(&told);
    options.on_written = Some(Arc::new(move |w: &hivepack::extract::Written<'_>| {
        into.lock().unwrap().push((w.path.join("/"), w.kind));
    }));
    told
}

#[test]
fn each_entry_written_is_told_and_none_left_out() {
    use hivepack::extract::{OnDamaged, WrittenKind as K};
    let mut data = zip(&[
        Entry::Dir(b"dir/"),
        Entry::File(b"dir/a.txt", b"hello"),
        Entry::Mode(b"to-a", b"dir/a.txt", 0o120_777),
        Entry::Stored(b"bad", b"0123456789"),
        Entry::File(b"b.txt", b"world"),
    ]);
    let at = data.windows(10).position(|w| w == b"0123456789").unwrap();
    data[at + 4] ^= 1;
    for (threads, damaged) in [(1, OnDamaged::Skip), (4, OnDamaged::Keep)] {
        let scratch = Scratch::new();
        let mut options = options(|o| {
            o.links = Links::Inside;
            o.threads = hivepack::Threads::Exactly(std::num::NonZeroU32::new(threads).unwrap());
            o.on_damaged = Some(Arc::new(move |_: &hivepack::extract::Error| damaged));
        });
        let told = told_of(&mut options);
        extract(&data, &scratch.out(), &options).unwrap();
        let mut told = told.lock().unwrap().clone();
        told.sort_by(|a, b| a.0.cmp(&b.0));
        let mut wanted = vec![
            ("b.txt".to_owned(), K::File),
            ("dir".to_owned(), K::Directory),
            ("dir/a.txt".to_owned(), K::File),
            ("to-a".to_owned(), K::Link),
        ];
        // A damaged file kept is written; one left out is not.
        if damaged == OnDamaged::Keep {
            wanted.push(("bad".to_owned(), K::File));
            wanted.sort_by(|a, b| a.0.cmp(&b.0));
        }
        assert_eq!(told, wanted, "{threads} threads, {damaged:?}");
    }
}
