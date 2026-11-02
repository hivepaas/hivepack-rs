//! The archives behind extraction CVEs, made again: each test builds the
//! kind of archive one advisory describes, and checks that it stops before
//! anything is written, or writes only inside the destination, as the
//! advisory's fix asks. docs/extract.md has the table of them.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "extract_support/mod.rs"]
mod support;

use hivepack::extract::{ErrorKind, Links, NameError, Names, OnRefused, Options, extract_zip};
use hivepack::zip::{Archive, OpenFlags};
use support::{Entry, Scratch, central_entries, extract, listing, options, patch_size, zip};

/// Renames the entry at `index` to `name`, of the same length, in its
/// local header and in the central directory: archives with names
/// hivepack::zip would not write twice.
fn patch_name(data: &mut [u8], index: usize, name: &[u8]) {
    let (central, _) = central_entries(data)[index];
    let len = u16::from_le_bytes([data[central + 28], data[central + 29]]) as usize;
    assert_eq!(len, name.len());
    data[central + 46..central + 46 + len].copy_from_slice(name);
    let local = u32::from_le_bytes(data[central + 42..central + 46].try_into().unwrap()) as usize;
    data[local + 30..local + 30 + len].copy_from_slice(name);
}

/// Extracts `data` opened without `ZIP_CHECKCONS`, for archives that
/// libzip's consistency check already refuses: what the extraction does on
/// its own.
fn extract_unchecked(
    data: &[u8],
    out: &std::path::Path,
    options: &Options,
) -> Result<hivepack::extract::Summary, hivepack::extract::Error> {
    assert!(Archive::open(data, OpenFlags::CHECKCONS).is_err());
    extract_zip(&Archive::open(data, OpenFlags(0)).unwrap(), out, options)
}

/// A link entry, as Info-ZIP's zip writes one: its target as its data.
fn link<'a>(name: &'a [u8], target: &'a [u8]) -> Entry<'a> {
    Entry::Mode(name, target, 0o120_777)
}

/// The `zip` crate's CVE-2025-29787 (RUSTSEC-2025-0168): a link earlier in
/// the archive, then a file written through it, outside the destination.
/// The link is refused; allowed, the file is on the way of a link, which
/// is the same path as the link.
#[test]
fn cve_2025_29787_a_file_through_a_link_of_the_archive() {
    let scratch = Scratch::new();
    let data = zip(&[
        link(b"link", b"../outside"),
        Entry::File(b"link/pwned", b"x"),
    ]);
    let error = extract(&data, &scratch.out(), &Options::default()).unwrap_err();
    assert!(matches!(error.kind, ErrorKind::Link), "{error}");
    let inside = options(|o| o.links = Links::Inside);
    let error = extract(&data, &scratch.out(), &inside).unwrap_err();
    assert!(
        matches!(error.kind, ErrorKind::Duplicate { first: 0 }),
        "{error}"
    );
    // Skipped instead: the link climbs out, and the file is under it.
    let skip = options(|o| {
        o.links = Links::Inside;
        o.on_refused = OnRefused::Skip;
    });
    let summary = extract(&data, &scratch.out(), &skip).unwrap();
    let reasons: Vec<_> = summary.skipped.iter().map(|e| &e.kind).collect();
    assert!(
        matches!(
            reasons[..],
            [
                ErrorKind::Duplicate { first: 0 },
                ErrorKind::LinkTarget(NameError::Dot)
            ]
        ),
        "{reasons:?}"
    );
    assert!(listing(&scratch.out()).is_empty());
    assert!(!scratch.path().join("outside").exists());
}

/// The `zip` crate's RUSTSEC-2026-0367: setuid, setgid and sticky bits
/// kept. Masked by default, and kept by no option.
#[cfg(unix)]
#[test]
fn rustsec_2026_0367_setuid_and_setgid_bits() {
    use hivepack::extract::Permissions;
    use std::os::unix::fs::PermissionsExt;
    let data = zip(&[Entry::Mode(b"tool", b"#!/bin/sh\n", 0o107_755)]);
    for permissions in [Permissions::Masked, Permissions::Preserve] {
        let scratch = Scratch::new();
        extract(
            &data,
            &scratch.out(),
            &options(|o| o.permissions = permissions),
        )
        .unwrap();
        let mode = std::fs::metadata(scratch.out().join("tool"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o7000, 0, "{permissions:?}: {mode:o}");
    }
}

/// The `zip` crate's RUSTSEC-2026-0368: links created whatever their
/// target, absolute or climbing out. Refused, even when links are
/// allowed; written as files, they hold only the target's text.
#[test]
fn rustsec_2026_0368_links_to_outside() {
    let data = zip(&[
        link(b"absolute", b"/etc/passwd"),
        link(b"climbing", b"../../../etc/passwd"),
    ]);
    let scratch = Scratch::new();
    let error = extract(&data, &scratch.out(), &Options::default()).unwrap_err();
    assert!(matches!(error.kind, ErrorKind::Link), "{error}");
    let inside = options(|o| {
        o.links = Links::Inside;
        o.on_refused = OnRefused::Skip;
    });
    let summary = extract(&data, &scratch.out(), &inside).unwrap();
    let reasons: Vec<_> = summary.skipped.iter().map(|e| &e.kind).collect();
    assert!(
        matches!(
            reasons[..],
            [
                ErrorKind::LinkTarget(NameError::Absolute),
                ErrorKind::LinkTarget(NameError::Dot)
            ]
        ),
        "{reasons:?}"
    );
    assert!(listing(&scratch.out()).is_empty());

    let scratch = Scratch::new();
    extract(&data, &scratch.out(), &options(|o| o.links = Links::AsFile)).unwrap();
    for (name, target) in [
        ("absolute", "/etc/passwd"),
        ("climbing", "../../../etc/passwd"),
    ] {
        let path = scratch.out().join(name);
        assert!(std::fs::symlink_metadata(&path).unwrap().is_file());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), target);
    }
}

/// The `zip` crate's RUSTSEC-2026-0369: a link to a file outside, then an
/// entry of the same name whose permissions were set through the link.
/// The same path twice is refused, the link's target too, and permissions
/// are set on the file's handle, never through a path.
#[cfg(unix)]
#[test]
fn rustsec_2026_0369_permissions_through_a_link() {
    use std::os::unix::fs::PermissionsExt;
    let scratch = Scratch::new();
    let victim = scratch.path().join("victim");
    std::fs::write(&victim, b"untouched").unwrap();
    std::fs::set_permissions(&victim, std::fs::Permissions::from_mode(0o600)).unwrap();
    let target = victim.to_str().unwrap().as_bytes().to_vec();
    let mut data = zip(&[
        link(b"evil", &target),
        Entry::Mode(b"evim", b"x", 0o100_777),
    ]);
    patch_name(&mut data, 1, b"evil");
    for links in [Links::Refuse, Links::Inside, Links::AsFile] {
        let out = scratch.path().join(format!("{links:?}"));
        let stop = extract_unchecked(&data, &out, &options(|o| o.links = links)).unwrap_err();
        assert!(
            matches!(
                stop.kind,
                ErrorKind::Link | ErrorKind::Duplicate { first: 0 }
            ),
            "{links:?}: {stop}"
        );
        let skip = options(|o| {
            o.links = links;
            o.on_refused = OnRefused::Skip;
        });
        extract_unchecked(&data, &out, &skip).unwrap();
    }
    let mode = std::fs::metadata(&victim).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o600);
    assert_eq!(std::fs::read(&victim).unwrap(), b"untouched");
}

/// adm-zip's CVE-2026-76845: links already in the destination, to a
/// directory and to a file outside it, written through. Directories are
/// opened without following a link, and files created new.
#[cfg(unix)]
#[test]
fn cve_2026_76845_links_already_in_the_destination() {
    let scratch = Scratch::new();
    let outside = scratch.path().join("outside");
    std::fs::create_dir(&outside).unwrap();
    let victim = scratch.path().join("victim");
    std::fs::write(&victim, b"untouched").unwrap();
    std::fs::create_dir(scratch.out()).unwrap();
    std::os::unix::fs::symlink(&outside, scratch.out().join("dir")).unwrap();
    std::os::unix::fs::symlink(&victim, scratch.out().join("file")).unwrap();

    let data = zip(&[Entry::File(b"dir/payload", b"x")]);
    let error = extract(&data, &scratch.out(), &Options::default()).unwrap_err();
    assert!(matches!(error.kind, ErrorKind::NotADirectory), "{error}");
    let data = zip(&[Entry::File(b"file", b"x")]);
    for overwrite in [false, true] {
        let error =
            extract(&data, &scratch.out(), &options(|o| o.overwrite = overwrite)).unwrap_err();
        assert!(matches!(error.kind, ErrorKind::Exists), "{error}");
    }
    assert!(listing(&outside).is_empty());
    assert_eq!(std::fs::read(&victim).unwrap(), b"untouched");
}

/// adm-zip's CVE-2026-39244: a small archive that declares 4 GB, which it
/// allocated. Nothing is allocated from a declared size: deflated data
/// ends short of it, the count of what was written says so, and the file
/// is removed. Stored data that short, libzip refuses on its own, at
/// opening with its consistency check and at reading without.
#[test]
fn cve_2026_39244_a_declared_size_is_not_allocated() {
    let mut data = zip(&[Entry::File(b"big", &[b'x'; 64])]);
    patch_size(&mut data, 0, 4_000_000_000);
    assert!(data.len() < 200, "{}", data.len());
    let scratch = Scratch::new();
    let started = std::time::Instant::now();
    let error = extract(&data, &scratch.out(), &Options::default()).unwrap_err();
    assert!(matches!(error.kind, ErrorKind::SizeMismatch), "{error}");
    assert!(started.elapsed().as_secs() < 5);
    assert!(listing(&scratch.out()).is_empty());
    // A lower limit stops it before anything is written.
    let scratch = Scratch::new();
    let low = options(|o| o.limits.max_entry_size = 1 << 30);
    let error = extract(&data, &scratch.out(), &low).unwrap_err();
    assert!(matches!(error.kind, ErrorKind::EntryTooLarge), "{error}");
    assert!(!scratch.out().exists());

    let mut stored = zip(&[Entry::Stored(b"big", b"x")]);
    patch_size(&mut stored, 0, 4_000_000_000);
    let scratch = Scratch::new();
    let error = extract_unchecked(&stored, &scratch.out(), &Options::default()).unwrap_err();
    assert!(matches!(error.kind, ErrorKind::Archive(_)), "{error}");
    assert!(listing(&scratch.out()).is_empty());
}

/// adm-zip's CVE-2026-92000: an entry that declares no data, which skipped
/// its output limit, with a megabyte of zeros. The first byte past what it
/// declares stops it.
#[test]
fn cve_2026_92000_an_entry_that_declares_nothing() {
    let zeros = vec![0u8; 1 << 20];
    let mut data = zip(&[Entry::File(b"empty", &zeros)]);
    patch_size(&mut data, 0, 0);
    let scratch = Scratch::new();
    let error = extract(&data, &scratch.out(), &Options::default()).unwrap_err();
    assert!(matches!(error.kind, ErrorKind::SizeMismatch), "{error}");
    assert!(listing(&scratch.out()).is_empty());
}

/// Fifield's quoted-overlap bombs, CPython's CVE-2024-0450, are
/// `extract::fifield_zip_bombs_write_nothing` (its `zbsm.zip` is one); a
/// short form of the same here: two entries, one stream.
#[test]
fn cve_2024_0450_entries_that_share_one_stream() {
    let data = zip(&[Entry::File(b"a", &[7; 1000])]);
    let (start, size) = central_entries(&data)[0];
    let mut copy = data[start..start + size].to_vec();
    copy[46] = b'b';
    let eocd = data.len() - 22;
    let mut bomb = data[..eocd].to_vec();
    bomb.extend_from_slice(&copy);
    let mut end = data[eocd..].to_vec();
    end[8] = 2;
    end[10] = 2;
    let cd_size = u32::from_le_bytes(end[12..16].try_into().unwrap()) + size as u32;
    end[12..16].copy_from_slice(&cd_size.to_le_bytes());
    bomb.extend_from_slice(&end);
    let scratch = Scratch::new();
    let archive = Archive::open(bomb.as_slice(), OpenFlags(0)).unwrap();
    let error = extract_zip(&archive, &scratch.out(), &Options::default()).unwrap_err();
    assert!(
        matches!(error.kind, ErrorKind::Overlap { other: 0 }),
        "{error}"
    );
    assert!(!scratch.out().exists());
}

/// WinRAR's CVE-2023-38831, exploited: a file and a folder of the same
/// name, `report.pdf ` and `report.pdf /`, whose folder held the script
/// that ran when the file was opened. The trailing space is refused, and
/// without it the two are the same path.
#[test]
fn cve_2023_38831_a_file_and_a_folder_of_one_name() {
    let scratch = Scratch::new();
    let data = zip(&[
        Entry::File(b"report.pdf ", b"%PDF"),
        Entry::File(b"report.pdf /report.pdf .cmd", b"calc"),
    ]);
    let error = extract(&data, &scratch.out(), &Options::default()).unwrap_err();
    assert!(
        matches!(error.kind, ErrorKind::Name(NameError::TrailingSpaceOrDot)),
        "{error}"
    );
    assert_eq!(error.index, Some(0));
    let data = zip(&[
        Entry::File(b"report.pdf", b"%PDF"),
        Entry::File(b"report.pdf/report.pdf.cmd", b"calc"),
    ]);
    let error = extract(&data, &scratch.out(), &Options::default()).unwrap_err();
    assert!(
        matches!(error.kind, ErrorKind::Duplicate { first: 0 }),
        "{error}"
    );
    assert!(!scratch.out().exists());
}

/// Android's Master Key, CVE-2013-4787: one name twice, one entry checked
/// and the other used. libzip's consistency check refuses it at opening,
/// and extraction refuses it without that check.
#[test]
fn cve_2013_4787_one_name_twice() {
    let mut data = zip(&[
        Entry::File(b"classes.dex", b"checked"),
        Entry::File(b"classes.dey", b"installed"),
    ]);
    patch_name(&mut data, 1, b"classes.dex");
    assert!(Archive::open(data.as_slice(), OpenFlags::CHECKCONS).is_err());
    let scratch = Scratch::new();
    let archive = Archive::open(data.as_slice(), OpenFlags(0)).unwrap();
    let error = extract_zip(&archive, &scratch.out(), &Options::default()).unwrap_err();
    assert!(
        matches!(error.kind, ErrorKind::Duplicate { first: 0 }),
        "{error}"
    );
    assert!(!scratch.out().exists());
}

/// node-tar's CVE-2021-37712: a link and a directory whose names are one
/// once normalized, which let a later file be written through the link.
/// Names are compared by their key, so they are the same path.
#[test]
fn cve_2021_37712_a_link_and_a_directory_one_by_normalization() {
    let scratch = Scratch::new();
    let data = zip(&[
        link("caf\u{e9}".as_bytes(), b"elsewhere"),
        Entry::Dir("cafe\u{301}/".as_bytes()),
        Entry::File("cafe\u{301}/x".as_bytes(), b"x"),
    ]);
    let inside = options(|o| o.links = Links::Inside);
    let error = extract(&data, &scratch.out(), &inside).unwrap_err();
    assert!(
        matches!(error.kind, ErrorKind::Duplicate { first: 0 }),
        "{error}"
    );
    assert_eq!(error.index, Some(1));
    assert!(!scratch.out().exists());
}

/// WinRAR's CVE-2025-8088, exploited: NTFS alternate data streams whose
/// names climb with `..\`, to the Startup folder. A colon or a backslash
/// is refused on every system, and so is the name once backslashes are
/// separators or names are cleaned up.
#[test]
fn cve_2025_8088_streams_that_climb() {
    let name: &[u8] = b"CV.pdf:..\\..\\..\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\evil.lnk";
    let data = zip(&[Entry::File(b"CV.pdf", b"%PDF"), Entry::File(name, b"lnk")]);
    for (options, reason) in [
        (Options::default(), NameError::Backslash),
        (options(|o| o.backslash_separator = true), NameError::Colon),
        (
            options(|o| {
                o.backslash_separator = true;
                o.names = Names::Sanitize;
            }),
            NameError::Colon,
        ),
    ] {
        let scratch = Scratch::new();
        let error = extract(&data, &scratch.out(), &options).unwrap_err();
        assert!(
            matches!(error.kind, ErrorKind::Name(e) if e == reason),
            "{error}"
        );
        assert_eq!(error.index, Some(1));
        assert!(!scratch.out().exists());
    }
}

/// 7-Zip's CVE-2026-58052: streams named `:Zone.Identifier:$DATA` and
/// `::$DATA`, which NTFS takes for the file's mark and its data, to
/// overwrite the propagated Mark of the Web and the file's content. The
/// colon is refused; skipped, the file alone is written.
#[test]
fn cve_2026_58052_streams_that_replace_the_mark() {
    let data = zip(&[
        Entry::File(b"setup.exe", b"MZ"),
        Entry::File(
            b"setup.exe:Zone.Identifier:$DATA",
            b"[ZoneTransfer]\r\nZoneId=0\r\n",
        ),
        Entry::File(b"setup.exe::$DATA", b"spoofed"),
    ]);
    let scratch = Scratch::new();
    let error = extract(&data, &scratch.out(), &Options::default()).unwrap_err();
    assert!(
        matches!(error.kind, ErrorKind::Name(NameError::Colon)),
        "{error}"
    );
    assert!(!scratch.out().exists());
    let summary = extract(
        &data,
        &scratch.out(),
        &options(|o| o.on_refused = OnRefused::Skip),
    )
    .unwrap();
    assert_eq!(summary.skipped.len(), 2);
    assert_eq!(listing(&scratch.out()), ["setup.exe"]);
    assert_eq!(
        std::fs::read(scratch.out().join("setup.exe")).unwrap(),
        b"MZ"
    );
}

/// 7-Zip's CVE-2025-0411, exploited: the Mark of the Web not carried to
/// what is extracted, so an archive inside an archive escapes it. Each
/// file gets the outer archive's mark, the inner archive too, and so what
/// is extracted from that.
#[cfg(windows)]
#[test]
fn cve_2025_0411_the_mark_through_nested_archives() {
    use hivepack::extract::Origin;
    let scratch = Scratch::new();
    let inner = zip(&[Entry::File(b"payload.exe", b"MZ")]);
    let outer_path = scratch.path().join("outer.zip");
    std::fs::write(&outer_path, zip(&[Entry::Stored(b"inner.zip", &inner)])).unwrap();
    let mark = b"[ZoneTransfer]\r\nZoneId=3\r\n";
    std::fs::write(format!("{}:Zone.Identifier", outer_path.display()), mark).unwrap();

    let outer = std::fs::read(&outer_path).unwrap();
    let origin = Origin::of(&outer_path).unwrap();
    extract(&outer, &scratch.out(), &options(|o| o.origin = origin)).unwrap();
    let inner_path = scratch.out().join("inner.zip");
    let origin = Origin::of(&inner_path).unwrap();
    assert_eq!(origin, Some(Origin::ZoneIdentifier(mark.to_vec())));
    let second = scratch.path().join("second");
    extract(&inner, &second, &options(|o| o.origin = origin)).unwrap();
    let stream = format!("{}:Zone.Identifier", second.join("payload.exe").display());
    assert_eq!(std::fs::read(stream).unwrap(), mark);
}

/// The quarantine of a file on macOS, if it has one.
#[cfg(target_os = "macos")]
fn quarantine(path: &std::path::Path) -> Option<Vec<u8>> {
    let mut value = Vec::with_capacity(1024);
    rustix::fs::getxattr(
        path,
        "com.apple.quarantine",
        rustix::buffer::spare_capacity(&mut value),
    )
    .ok()
    .map(|_| value)
}

/// macOS's CVE-2021-1810: Archive Utility left the quarantine off files
/// whose path was longer than 886 characters. The mark is set on each
/// file's descriptor, whatever its path.
#[cfg(target_os = "macos")]
#[test]
fn cve_2021_1810_the_quarantine_on_long_paths() {
    use hivepack::extract::Origin;
    let mark = b"0083;6720f5a0;Safari;".to_vec();
    let deep = format!("{0}/{0}/{0}/{0}/payload", "a".repeat(220));
    assert!(deep.len() > 886);
    let data = zip(&[Entry::File(deep.as_bytes(), b"x")]);
    let scratch = Scratch::new();
    extract(
        &data,
        &scratch.out(),
        &options(|o| o.origin = Some(Origin::Quarantine(mark.clone()))),
    )
    .unwrap();
    assert_eq!(quarantine(&scratch.out().join(&deep)), Some(mark));
}

/// macOS's CVE-2022-42821 ("Achilles"): an AppleDouble file beside an app,
/// `._Some.app`, whose ACL, once applied, kept the quarantine from being
/// set. AppleDouble files are not applied: written as the files they are,
/// and the app gets the mark.
#[cfg(target_os = "macos")]
#[test]
fn cve_2022_42821_appledouble_is_not_applied() {
    use hivepack::extract::Origin;
    let mark = b"0083;6720f5a0;Safari;".to_vec();
    // AppleDouble's magic and version, then what would be its entries.
    let appledouble =
        b"\x00\x05\x16\x07\x00\x02\x00\x00com.apple.acl.text everyone deny writeextattr";
    let data = zip(&[
        Entry::File(b"Some.app/Contents/MacOS/some", b"x"),
        Entry::File(b"._Some.app", appledouble),
    ]);
    let scratch = Scratch::new();
    extract(
        &data,
        &scratch.out(),
        &options(|o| o.origin = Some(Origin::Quarantine(mark.clone()))),
    )
    .unwrap();
    for item in ["Some.app", "Some.app/Contents/MacOS/some", "._Some.app"] {
        assert_eq!(
            quarantine(&scratch.out().join(item)),
            Some(mark.clone()),
            "{item}"
        );
    }
    let appledouble_file = scratch.out().join("._Some.app");
    assert_eq!(std::fs::read(appledouble_file).unwrap(), appledouble);
}

/// Python's CVE-2025-4138 in a ZIP archive: a target inside by its text, where
/// the system goes through another link of the archive and out.
#[cfg(unix)]
#[test]
fn cve_2025_4138_a_target_inside_by_its_text_only() {
    let scratch = Scratch::new();
    std::fs::write(scratch.path().join("secret"), b"outside").unwrap();
    let data = zip(&[
        Entry::Dir(b"a/"),
        link(b"a/up", b".."),
        link(b"esc", b"a/up/../secret"),
    ]);
    let inside = options(|o| o.links = Links::Inside);
    let error = extract(&data, &scratch.out(), &inside).unwrap_err();
    assert!(
        matches!(error.kind, ErrorKind::LinkChain { other: 1 }),
        "{error}"
    );
    assert!(!scratch.out().exists());
}
