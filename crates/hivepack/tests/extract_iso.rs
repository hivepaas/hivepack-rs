//! Extracting ISO 9660 images made to attack extractors, as `tests/tar.rs`
//! does for tar: Rock Ridge names that climb out, the same path twice,
//! symbolic and hard links, devices, the limits, images cut short, a
//! zisofs file, entries libarchive gives with something missing, and an
//! image that changes between its two readings. Each must stop with its
//! reason and leave nothing outside the destination, and nothing at all
//! when the checks before writing stop it. Then libarchive's test images,
//! each extracted or stopped with its reason.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "extract_support/mod.rs"]
mod support;

use std::cell::Cell;
use std::io::Cursor;
use std::path::Path;

use hivepack::deflate::{Deflate, Flush, InBuffer, OutBuffer, Status};
use hivepack::extract::{ErrorKind, Links, NameError, OnRefused, Options, Summary, extract_iso};
use support::{Scratch, listing, options};

const BLOCK: usize = 2048;

/// What an entry of a test image is.
#[derive(Clone)]
enum What<'a> {
    Dir,
    File(&'a [u8]),
    /// A file compressed with zisofs, its last block of zeros written as
    /// an empty block, as mkzftree writes it.
    Zisofs(&'a [u8]),
    Symlink(&'a [u8]),
    /// A character device.
    Device,
    /// A second name for the file at this index: the same extent and
    /// serial number.
    Link(usize),
    /// A file whose extent is at location 0 and past the volume's end.
    PastTheEnd,
}

/// An entry: its Rock Ridge names from the root, one per component, as
/// bytes, so that they can be anything.
#[derive(Clone)]
struct E<'a> {
    path: &'a [&'a [u8]],
    what: What<'a>,
}

fn both32(v: u32) -> [u8; 8] {
    let mut b = [0; 8];
    b[..4].copy_from_slice(&v.to_le_bytes());
    b[4..].copy_from_slice(&v.to_be_bytes());
    b
}

fn su(sig: &[u8; 2], data: &[u8]) -> Vec<u8> {
    let mut e = vec![sig[0], sig[1], (4 + data.len()) as u8, 1];
    e.extend_from_slice(data);
    e
}

/// A Rock Ridge PX entry: mode, links, owner, group and serial number.
fn px(mode: u32, ino: u32) -> Vec<u8> {
    let mut data = Vec::new();
    for v in [mode, 1, 0, 0, ino] {
        data.extend_from_slice(&both32(v));
    }
    su(b"PX", &data)
}

/// A directory record, dated 2020-09-13 (1,600,000,000 is 12:26:40).
fn record(extent: u32, size: u32, flags: u8, name: &[u8], system_use: &[u8]) -> Vec<u8> {
    let pad = usize::from(name.len().is_multiple_of(2));
    let len = 33 + name.len() + pad + system_use.len();
    let mut r = vec![0u8; len];
    r[0] = len as u8;
    r[2..10].copy_from_slice(&both32(extent));
    r[10..18].copy_from_slice(&both32(size));
    r[18..25].copy_from_slice(&[120, 9, 13, 12, 26, 40, 0]);
    r[25] = flags;
    r[28..32].copy_from_slice(&[1, 0, 0, 1]);
    r[32] = name.len() as u8;
    r[33..33 + name.len()].copy_from_slice(name);
    r[33 + name.len() + pad..].copy_from_slice(system_use);
    r
}

/// A zlib stream of `data`.
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

/// `data` compressed with zisofs, in blocks of 32 KiB, a block of zeros
/// as an empty one.
fn zisofs(data: &[u8]) -> Vec<u8> {
    let blocks = data.len().div_ceil(1 << 15);
    let mut out = vec![0x37, 0xE4, 0x53, 0x96, 0xC9, 0xDB, 0xD6, 0x07];
    out.extend_from_slice(&(data.len() as u32).to_le_bytes());
    out.extend_from_slice(&[4, 15, 0, 0]);
    let pointers = out.len();
    out.resize(pointers + (blocks + 1) * 4, 0);
    let mut offsets = vec![out.len() as u32];
    for chunk in data.chunks(1 << 15) {
        if chunk.iter().any(|&b| b != 0) {
            out.extend_from_slice(&zlib(chunk));
        }
        offsets.push(out.len() as u32);
    }
    for (i, off) in offsets.iter().enumerate() {
        out[pointers + 4 * i..pointers + 4 * i + 4].copy_from_slice(&off.to_le_bytes());
    }
    out
}

/// An image of `entries`, with Rock Ridge (or ISO 9660's own names, made
/// up, without it). Directories that paths go through are made.
fn image(entries: &[E<'_>], rock_ridge: bool) -> Vec<u8> {
    // The directories, by their paths, the root first.
    let mut dirs: Vec<Vec<&[u8]>> = vec![Vec::new()];
    for e in entries {
        let upto = if matches!(e.what, What::Dir) {
            e.path.len()
        } else {
            e.path.len() - 1
        };
        for end in 1..=upto {
            if !dirs.iter().any(|d| d[..] == e.path[..end]) {
                dirs.push(e.path[..end].to_vec());
            }
        }
    }
    // Sectors: 16 the PVD, 17 the terminator, 18 the path table, then a
    // sector each directory, then the files' data.
    let dir_at = |d: usize| 19 + d as u32;
    let mut next = dir_at(dirs.len());
    let mut data_at = vec![(0u32, 0u32); entries.len()];
    let mut out = vec![0u8; next as usize * BLOCK];
    for (i, e) in entries.iter().enumerate() {
        let bytes = match &e.what {
            What::File(data) => data.to_vec(),
            What::Zisofs(data) => zisofs(data),
            _ => continue,
        };
        data_at[i] = (next, bytes.len() as u32);
        out.resize(next as usize * BLOCK, 0);
        out.extend_from_slice(&bytes);
        next += bytes.len().div_ceil(BLOCK).max(1) as u32;
        out.resize(next as usize * BLOCK, 0);
    }
    for (d, dir) in dirs.iter().enumerate() {
        let parent = dirs
            .iter()
            .position(|p| !dir.is_empty() && p[..] == dir[..dir.len() - 1])
            .unwrap_or(0);
        let mut root_su = Vec::new();
        if rock_ridge && d == 0 {
            root_su = su(b"SP", &[0xbe, 0xef, 0]);
            root_su.extend(px(0o40755, 1));
        }
        let mut records = vec![
            record(dir_at(d), BLOCK as u32, 2, &[0], &root_su),
            record(dir_at(parent), BLOCK as u32, 2, &[1], &[]),
        ];
        for (k, sub) in dirs
            .iter()
            .enumerate()
            .filter(|(_, s)| s.len() == dir.len() + 1 && s[..dir.len()] == dir[..])
        {
            let mut rr = px(0o40750, 10 + k as u32);
            let mut nm = vec![0];
            nm.extend_from_slice(sub[sub.len() - 1]);
            rr.extend(su(b"NM", &nm));
            let name = format!("D{k}");
            records.push(record(
                dir_at(k),
                BLOCK as u32,
                2,
                name.as_bytes(),
                if rock_ridge { &rr } else { &[] },
            ));
        }
        for (i, e) in entries.iter().enumerate() {
            if matches!(e.what, What::Dir)
                || e.path.len() != dir.len() + 1
                || e.path[..dir.len()] != dir[..]
            {
                continue;
            }
            let mut nm = vec![0];
            nm.extend_from_slice(e.path[e.path.len() - 1]);
            let ino = 1000 + i as u32;
            let (extent, size, mut rr) = match &e.what {
                What::File(_) => (data_at[i].0, data_at[i].1, px(0o100640, ino)),
                What::Zisofs(data) => {
                    let mut rr = px(0o100640, ino);
                    let mut zf = vec![b'p', b'z', 4, 15];
                    zf.extend_from_slice(&both32(data.len() as u32));
                    rr.extend(su(b"ZF", &zf));
                    (data_at[i].0, data_at[i].1, rr)
                }
                What::Symlink(target) => {
                    let mut rr = px(0o120777, ino);
                    let mut sl = vec![0];
                    for (c, part) in target.split(|&b| b == b'/').enumerate() {
                        match part {
                            b"" if c == 0 => sl.extend([0x08, 0]),
                            b".." => sl.extend([0x04, 0]),
                            b"." => sl.extend([0x02, 0]),
                            text => {
                                sl.extend([0, text.len() as u8]);
                                sl.extend_from_slice(text);
                            }
                        }
                    }
                    rr.extend(su(b"SL", &sl));
                    (0, 0, rr)
                }
                What::Device => {
                    let mut rr = px(0o20644, ino);
                    let mut pn = both32(0).to_vec();
                    pn.extend_from_slice(&both32(5));
                    rr.extend(su(b"PN", &pn));
                    (0, 0, rr)
                }
                What::Link(target) => (
                    data_at[*target].0,
                    data_at[*target].1,
                    px(0o100640, 1000 + *target as u32),
                ),
                What::PastTheEnd => (0, 1 << 30, px(0o100640, ino)),
                What::Dir => unreachable!(),
            };
            rr.extend(su(b"NM", &nm));
            let name = format!("F{i}.TXT;1");
            records.push(record(
                extent,
                size,
                0,
                name.as_bytes(),
                if rock_ridge { &rr } else { &[] },
            ));
        }
        let packed: Vec<u8> = records.concat();
        assert!(packed.len() <= BLOCK, "a directory of one sector");
        let at = dir_at(d) as usize * BLOCK;
        out[at..at + packed.len()].copy_from_slice(&packed);
    }
    // libarchive looks at 48 KiB before it says an image is one.
    next = next.max(26);
    out.resize(next as usize * BLOCK, 0);
    // The volume descriptors.
    let mut pvd = vec![0u8; BLOCK];
    pvd[..7].copy_from_slice(b"\x01CD001\x01");
    pvd[8..72].fill(b' ');
    pvd[80..88].copy_from_slice(&both32(next));
    pvd[120..124].copy_from_slice(&[1, 0, 0, 1]);
    pvd[124..128].copy_from_slice(&[1, 0, 0, 1]);
    pvd[128..132].copy_from_slice(&[0, 8, 8, 0]);
    pvd[132..140].copy_from_slice(&both32(10));
    pvd[140..144].copy_from_slice(&18u32.to_le_bytes());
    pvd[156..190].copy_from_slice(&record(dir_at(0), BLOCK as u32, 2, &[0], &[]));
    pvd[881] = 1;
    out[16 * BLOCK..17 * BLOCK].copy_from_slice(&pvd);
    out[17 * BLOCK..17 * BLOCK + 7].copy_from_slice(b"\xffCD001\x01");
    out
}

fn extract(
    data: &[u8],
    out: &Path,
    options: &Options,
) -> Result<Summary, hivepack::extract::Error> {
    extract_iso(|| Ok(Cursor::new(data.to_vec())), out, options)
}

fn read(path: &Path) -> Vec<u8> {
    std::fs::read(path).unwrap()
}

#[test]
fn extracts_directories_files_and_rock_ridge_names() {
    let scratch = Scratch::new();
    let big: Vec<u8> = (0..10_000u32).map(|i| (i % 251) as u8).collect();
    let iso = image(
        &[
            E {
                path: &[b"docs"],
                what: What::Dir,
            },
            E {
                path: &[b"docs", "résumé, long name.txt".as_bytes()],
                what: What::File(b"hello\n"),
            },
            E {
                path: &[b"deep", b"er", b"est.bin"],
                what: What::File(&big),
            },
            E {
                path: &[b"empty"],
                what: What::File(b""),
            },
        ],
        true,
    );
    let summary = extract(&iso, &scratch.out(), &portable()).unwrap();
    assert_eq!((summary.files, summary.directories), (3, 3));
    assert_eq!(
        listing(&scratch.out()),
        [
            "deep/",
            "deep/er/",
            "deep/er/est.bin",
            "docs/",
            "docs/résumé, long name.txt",
            "empty"
        ]
    );
    assert_eq!(
        read(&scratch.out().join("docs/résumé, long name.txt")),
        b"hello\n"
    );
    assert_eq!(read(&scratch.out().join("deep/er/est.bin")), big);
    let modified = std::fs::metadata(scratch.out().join("empty"))
        .unwrap()
        .modified()
        .unwrap();
    let secs = modified
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    assert_eq!(secs, 1_600_000_000);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // Rock Ridge's 0640, masked: readable and writable by the owner.
        let mode = std::fs::metadata(scratch.out().join("empty"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o640);
    }
}

#[test]
fn without_rock_ridge_names_are_iso_9660_s_and_permissions_the_system_s() {
    let scratch = Scratch::new();
    let iso = image(
        &[E {
            path: &[b"x"],
            what: What::File(b"data"),
        }],
        false,
    );
    extract(&iso, &scratch.out(), &portable()).unwrap();
    // The version ";1" is not part of the name.
    assert_eq!(listing(&scratch.out()), ["F0.TXT"]);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // Not libarchive's 0400: what the system gives a new file.
        let mode = std::fs::metadata(scratch.out().join("F0.TXT"))
            .unwrap()
            .permissions()
            .mode();
        assert_ne!(mode & 0o200, 0, "{mode:o}");
    }
}

#[test]
fn refused_names_write_nothing() {
    for path in [
        &[&b"../escape"[..]][..],
        &[b"a", b".."],
        &[b"/etc"],
        &[b"con"],
        &[b"a:b"],
    ] {
        let scratch = Scratch::new();
        let iso = image(
            &[
                E {
                    path: &[b"fine"],
                    what: What::File(b"1"),
                },
                E {
                    path,
                    what: What::File(b"2"),
                },
            ],
            true,
        );
        let e = extract(&iso, &scratch.out(), &portable()).unwrap_err();
        assert!(matches!(e.kind, ErrorKind::Name(_)), "{path:?}: {e}");
        assert!(!scratch.out().exists(), "{path:?}");
        assert_eq!(listing(scratch.path()), Vec::<String>::new());
    }
    // Skipped, the rest extracts.
    let scratch = Scratch::new();
    let iso = image(
        &[
            E {
                path: &[b"fine"],
                what: What::File(b"1"),
            },
            E {
                path: &[b"../escape"],
                what: What::File(b"2"),
            },
        ],
        true,
    );
    let summary = extract(
        &iso,
        &scratch.out(),
        &options(|o| o.on_refused = OnRefused::Skip),
    )
    .unwrap();
    assert_eq!(listing(&scratch.out()), ["fine"]);
    assert!(matches!(
        summary.skipped[0].kind,
        ErrorKind::Name(NameError::Dot)
    ));
}

#[test]
fn the_same_path_twice_is_refused() {
    let scratch = Scratch::new();
    let iso = image(
        &[
            E {
                path: &[b"Readme"],
                what: What::File(b"1"),
            },
            E {
                path: &[b"README"],
                what: What::File(b"2"),
            },
        ],
        true,
    );
    let e = extract(&iso, &scratch.out(), &portable()).unwrap_err();
    assert!(matches!(e.kind, ErrorKind::Duplicate { .. }), "{e}");
    assert!(!scratch.out().exists());
}

#[test]
fn symbolic_links_follow_the_options() {
    let entries = [
        E {
            path: &[b"file"],
            what: What::File(b"target"),
        },
        E {
            path: &[b"inside"],
            what: What::Symlink(b"file"),
        },
        E {
            path: &[b"outside"],
            what: What::Symlink(b"../../etc/passwd"),
        },
    ];
    let iso = image(&entries, true);
    // Refused by default.
    let scratch = Scratch::new();
    let e = extract(&iso, &scratch.out(), &portable()).unwrap_err();
    assert!(matches!(e.kind, ErrorKind::Link), "{e}");
    // Written as files holding their target.
    let scratch = Scratch::new();
    extract(&iso, &scratch.out(), &options(|o| o.links = Links::AsFile)).unwrap();
    assert_eq!(read(&scratch.out().join("outside")), b"../../etc/passwd");
    // Created when they stay inside; the other refused.
    let scratch = Scratch::new();
    let e = extract(&iso, &scratch.out(), &options(|o| o.links = Links::Inside)).unwrap_err();
    assert!(
        matches!(e.kind, ErrorKind::LinkTarget(NameError::Dot)),
        "{e}"
    );
    #[cfg(unix)]
    {
        let scratch = Scratch::new();
        let summary = extract(
            &image(&entries[..2], true),
            &scratch.out(),
            &options(|o| o.links = Links::Inside),
        )
        .unwrap();
        assert_eq!(summary.links, 1);
        assert_eq!(read(&scratch.out().join("inside")), b"target");
    }
}

#[test]
fn hard_links_name_the_file_before_them() {
    let iso = image(
        &[
            E {
                path: &[b"a"],
                what: What::File(b"shared data"),
            },
            E {
                path: &[b"b"],
                what: What::Link(0),
            },
        ],
        true,
    );
    let scratch = Scratch::new();
    let summary = extract(&iso, &scratch.out(), &portable()).unwrap();
    assert_eq!(summary.files, 2);
    assert_eq!(read(&scratch.out().join("b")), b"shared data");
    // A copy, with Links::AsFile, counted as written.
    let scratch = Scratch::new();
    let summary = extract(&iso, &scratch.out(), &options(|o| o.links = Links::AsFile)).unwrap();
    assert_eq!((summary.files, summary.bytes), (2, 22));
}

#[test]
fn devices_are_not_created() {
    let iso = image(
        &[
            E {
                path: &[b"null"],
                what: What::Device,
            },
            E {
                path: &[b"file"],
                what: What::File(b"x"),
            },
        ],
        true,
    );
    let scratch = Scratch::new();
    let e = extract(&iso, &scratch.out(), &portable()).unwrap_err();
    assert!(matches!(e.kind, ErrorKind::Special), "{e}");
    let scratch = Scratch::new();
    let summary = extract(
        &iso,
        &scratch.out(),
        &options(|o| o.on_refused = OnRefused::Skip),
    )
    .unwrap();
    assert_eq!(listing(&scratch.out()), ["file"]);
    assert!(matches!(summary.skipped[0].kind, ErrorKind::Special));
}

#[test]
fn limits_stop_before_writing() {
    let data = vec![7u8; 5000];
    let iso = image(
        &[
            E {
                path: &[b"first"],
                what: What::File(b"x"),
            },
            E {
                path: &[b"big"],
                what: What::File(&data),
            },
        ],
        true,
    );
    let scratch = Scratch::new();
    let e = extract(
        &iso,
        &scratch.out(),
        &options(|o| o.limits.max_entry_size = 4999),
    )
    .unwrap_err();
    assert!(matches!(e.kind, ErrorKind::EntryTooLarge), "{e}");
    assert!(!scratch.out().exists());
    let e = extract(
        &iso,
        &scratch.out(),
        &options(|o| o.limits.max_total_size = 5000),
    )
    .unwrap_err();
    assert!(matches!(e.kind, ErrorKind::TotalTooLarge), "{e}");
    let e = extract(&iso, &scratch.out(), &options(|o| o.limits.max_entries = 2)).unwrap_err();
    assert!(matches!(e.kind, ErrorKind::TooManyEntries), "{e}");
    assert!(!scratch.out().exists());
}

#[test]
fn an_image_cut_short_stops_before_writing() {
    let data = vec![9u8; 60_000];
    let iso = image(
        &[
            E {
                path: &[b"first"],
                what: What::File(b"x"),
            },
            E {
                path: &[b"last"],
                what: What::File(&data),
            },
        ],
        true,
    );
    // Cut in the last file's data, which nothing comes after: the first
    // reading reads it.
    let end = iso.iter().rposition(|&b| b == 9).unwrap();
    let cut = &iso[..end - 1000];
    let scratch = Scratch::new();
    let e = extract(cut, &scratch.out(), &portable()).unwrap_err();
    assert!(
        matches!(e.kind, ErrorKind::Iso(hivepack::iso::Error::TruncatedFile)),
        "{e}"
    );
    assert!(!scratch.out().exists());
}

#[test]
fn zisofs_files_are_written_to_their_size() {
    // Blocks of 32 KiB: data, zeros (an empty block), data, then zeros to
    // the end, which libarchive does not give: they come out as zeros.
    let mut data = b"compressed ".repeat(3000);
    data.resize(1 << 16, 0);
    data.extend(b"more ".repeat(1000));
    data.resize(150_000, 0);
    let iso = image(
        &[E {
            path: &[b"z"],
            what: What::Zisofs(&data),
        }],
        true,
    );
    let scratch = Scratch::new();
    let summary = extract(&iso, &scratch.out(), &portable()).unwrap();
    assert_eq!(summary.bytes, 150_000);
    assert_eq!(read(&scratch.out().join("z")), data);
}

#[test]
fn entries_with_something_missing_are_refused() {
    let iso = image(
        &[
            E {
                path: &[b"fine"],
                what: What::File(b"1"),
            },
            E {
                path: &[b"gone"],
                what: What::PastTheEnd,
            },
        ],
        true,
    );
    let scratch = Scratch::new();
    let e = extract(&iso, &scratch.out(), &portable()).unwrap_err();
    assert!(
        matches!(
            e.kind,
            ErrorKind::IsoEntry(hivepack::iso::Warning::FileBeyondEnd { .. })
        ),
        "{e}"
    );
    assert_eq!(e.name.as_deref(), Some(&b"gone"[..]));
    assert!(!scratch.out().exists());
    let summary = extract(
        &iso,
        &scratch.out(),
        &options(|o| o.on_refused = OnRefused::Skip),
    )
    .unwrap();
    assert_eq!(listing(&scratch.out()), ["fine"]);
    assert_eq!(summary.skipped.len(), 1);
}

#[test]
fn an_image_that_changes_between_readings_stops() {
    let first = image(
        &[E {
            path: &[b"a"],
            what: What::File(b"one"),
        }],
        true,
    );
    let second = image(
        &[E {
            path: &[b"b"],
            what: What::File(b"one"),
        }],
        true,
    );
    let readings = Cell::new(0);
    let scratch = Scratch::new();
    let e = extract_iso(
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
    assert_eq!(readings.get(), 2);
}

/// libarchive's test images, uncompressed.
fn libarchive_images() -> Vec<(String, Vec<u8>)> {
    let folder = support::repository().join("testdata/libarchive-iso");
    let mut paths: Vec<_> = std::fs::read_dir(folder)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|e| e == "xz"))
        .collect();
    paths.sort();
    paths
        .into_iter()
        .map(|p| {
            let name = p
                .file_name()
                .unwrap()
                .to_string_lossy()
                .replace(".iso.xz", "");
            (name, support::xz_decode(&std::fs::read(&p).unwrap()))
        })
        .collect()
}

#[test]
fn libarchive_test_images_extract_or_stop_with_their_reason() {
    for (name, image) in libarchive_images() {
        // Creating a link on Windows takes a privilege most accounts lack.
        let choices: &[Links] = if cfg!(unix) {
            &[Links::Refuse, Links::AsFile, Links::Inside]
        } else {
            &[Links::Refuse, Links::AsFile]
        };
        for &links in choices {
            let scratch = Scratch::new();
            let options = options(|o| {
                o.links = links;
                o.on_refused = OnRefused::Skip;
            });
            let outcome = extract(&image, &scratch.out(), &options);
            // Nothing beside the destination, whatever happened.
            for path in listing(scratch.path()) {
                assert!(path.starts_with("out/") || path == "out/", "{name}: {path}");
            }
            let outcome = match outcome {
                Ok(summary) => {
                    format!("{} files, {} skipped", summary.files, summary.skipped.len())
                }
                Err(e) => format!("stopped: {e}"),
            };
            eprintln!("{name} {links:?}: {outcome}");
            // The images whose damage libarchive stops at.
            // The images of damage libarchive stops at, and only those.
            let damaged = ["utf16be_overflow", "ce_loop", "ce_overflow", "cl_re_cycle"]
                .iter()
                .any(|d| name.ends_with(d));
            assert_eq!(outcome.starts_with("stopped"), damaged, "{name}: {outcome}");
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
