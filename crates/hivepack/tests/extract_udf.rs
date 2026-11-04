//! Extracting UDF volumes that hivepack::udf mounts: the images of
//! `testdata/udf`, made with mkudffs and genisoimage and filled through
//! Linux, extracted as Linux reads them (each file's SHA-256 the same, the
//! entries refused for their reason); and images changed to attack: a
//! file's data past the image, a directory named twice. Nothing may be left outside the
//! destination, and nothing at all when the checks before writing stop it.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "extract_support/mod.rs"]
mod support;

use std::collections::HashMap;
use std::io::Cursor;
use std::path::{Path, PathBuf};

use hivepack::extract::{ErrorKind, Links, NameError, OnRefused, Options, Summary, extract_udf};
use hivepack::udf::Udf;
use support::{Scratch, listing, options};

/// The image `testdata/udf/<name>.udf.xz`, and what Linux reads of it.
fn image(name: &str) -> (Vec<u8>, String) {
    let dir = support::repository().join("testdata/udf");
    let image = support::xz_decode(&std::fs::read(dir.join(format!("{name}.udf.xz"))).unwrap());
    let answer = std::fs::read_to_string(dir.join(format!("{name}.txt"))).unwrap();
    (image, answer)
}

fn extract(
    image: &[u8],
    out: &Path,
    options: &Options,
) -> Result<Summary, hivepack::extract::Error> {
    let mut udf = Udf::open(Cursor::new(image.to_vec())).unwrap();
    extract_udf(&mut udf, out, options)
}

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn sha256(data: &[u8]) -> String {
    let mut h = hivepack::crypto::Sha256::new();
    h.update(data);
    h.out().iter().map(|b| format!("{b:02x}")).collect()
}

/// A path of the volume under `out`.
fn under(out: &Path, path: &[u8]) -> PathBuf {
    out.join(std::str::from_utf8(path).unwrap())
}

/// What Linux reads: path, type, link target, SHA-256.
fn answers(answer: &str) -> Vec<(Vec<u8>, char, Vec<u8>, String)> {
    answer
        .lines()
        .filter(|l| !l.starts_with('#'))
        .map(|line| {
            let f: Vec<&str> = line.split('\t').collect();
            let path = if f[0] == "." { Vec::new() } else { hex(f[0]) };
            let target = if f[1] == "l" && f[10] != "-" {
                hex(f[10])
            } else {
                Vec::new()
            };
            (
                path,
                f[1].chars().next().unwrap(),
                target,
                f[11].to_string(),
            )
        })
        .collect()
}

#[test]
fn volumes_extract_as_linux_reads_them() {
    for name in [
        "mkudffs-hd-0102",
        "mkudffs-hd-0201",
        "mkudffs-hd-0201-bs4096",
        "mkudffs-cdrw-0201",
        "mkudffs-dvdr-0250",
        "genisoimage",
    ] {
        let (image, answer) = image(name);
        // Creating a link on Windows takes a privilege most accounts lack.
        let choices: &[Links] = if cfg!(unix) {
            &[Links::AsFile, Links::Inside]
        } else {
            &[Links::AsFile]
        };
        for &links in choices {
            let scratch = Scratch::new();
            let out = scratch.out();
            let options = options(|o| {
                o.links = links;
                o.on_refused = OnRefused::Skip;
            });
            let summary = extract(&image, &out, &options).unwrap_or_else(|e| panic!("{name}: {e}"));
            for path in listing(scratch.path()) {
                assert!(path.starts_with("out/") || path == "out/", "{name}: {path}");
            }
            let skipped: HashMap<Vec<u8>, &ErrorKind> = summary
                .skipped
                .iter()
                .map(|e| (e.name.clone().unwrap_or_default(), &e.kind))
                .collect();
            for (path, kind, target, digest) in answers(&answer) {
                if path.is_empty() {
                    continue;
                }
                let at = under(&out, &path);
                let shown = String::from_utf8_lossy(&path).into_owned();
                if let Some(why) = skipped.get(&path) {
                    // Refused for its name, its kind, or its link's target.
                    assert!(
                        matches!(
                            why,
                            ErrorKind::Name(_) | ErrorKind::Special | ErrorKind::LinkTarget(_)
                        ),
                        "{name}: {shown}: {why}"
                    );
                    assert!(at.symlink_metadata().is_err(), "{name}: {shown}");
                    continue;
                }
                match kind {
                    'd' => assert!(at.is_dir(), "{name}: {shown}"),
                    'f' => assert_eq!(
                        sha256(&std::fs::read(&at).unwrap()),
                        digest,
                        "{name}: {shown}"
                    ),
                    'l' if links == Links::AsFile => {
                        assert_eq!(std::fs::read(&at).unwrap(), target, "{name}: {shown}")
                    }
                    'l' => {
                        let read = std::fs::read_link(&at).unwrap();
                        assert_eq!(read.to_str().unwrap().as_bytes(), target, "{name}: {shown}");
                    }
                    _ => panic!("{name}: {shown}: a {kind} not refused"),
                }
            }
        }
    }
}

#[test]
fn refusals_name_their_reason() {
    let (image, _) = image("mkudffs-hd-0201");
    let scratch = Scratch::new();
    let summary = extract(
        &image,
        &scratch.out(),
        &options(|o| {
            o.links = Links::Inside;
            o.on_refused = OnRefused::Skip;
        }),
    )
    .unwrap();
    let mut reasons: Vec<(String, String)> = summary
        .skipped
        .iter()
        .map(|e| {
            (
                String::from_utf8_lossy(e.name.as_deref().unwrap_or_default()).into_owned(),
                e.kind.to_string(),
            )
        })
        .collect();
    reasons.sort();
    let names: Vec<&str> = reasons.iter().map(|(n, _)| n.as_str()).collect();
    assert_eq!(
        names,
        [
            "a:b*c?d \"e\" <f>|g\\h",
            "absolute",
            "block-dev",
            "char",
            "fifo"
        ],
        "{reasons:?}"
    );
    assert!(
        summary
            .skipped
            .iter()
            .any(|e| matches!(e.kind, ErrorKind::LinkTarget(NameError::Absolute)))
    );
    // The hard link is one file under two names.
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let a = std::fs::metadata(scratch.out().join("small")).unwrap();
        let b = std::fs::metadata(scratch.out().join("hard")).unwrap();
        assert_eq!(a.ino(), b.ino());
    }
    // By default, the first refusal stops it before anything is written.
    let scratch = Scratch::new();
    let e = extract(&image, &scratch.out(), &portable()).unwrap_err();
    assert!(
        matches!(
            e.kind,
            ErrorKind::Name(_) | ErrorKind::Link | ErrorKind::Special
        ),
        "{e}"
    );
    assert!(
        listing(scratch.path()).is_empty(),
        "{:?}",
        listing(scratch.path())
    );
}

#[test]
fn data_not_on_the_image_stops_before_writing() {
    // The large file's extent moved to the end of its partition, past it:
    // what an image cut short is to it.
    let (mut image, _) = image("mkudffs-hd-0201");
    let fe = (0..image.len() / 512)
        .map(|s| s * 512)
        .find(|&at| {
            tagged(&image, at, [10, 1]) && image[at + 56..at + 64] == 5_000_000u64.to_le_bytes()
        })
        .unwrap();
    let l_ea = u32::from_le_bytes(image[fe + 208..fe + 212].try_into().unwrap()) as usize;
    let ad = fe + 216 + l_ea;
    let pd = (0..image.len() / 512)
        .map(|s| s * 512)
        .find(|&at| tagged(&image, at, [5, 0]))
        .unwrap();
    let part_len = u32::from_le_bytes(image[pd + 192..pd + 196].try_into().unwrap());
    image[ad + 4..ad + 8].copy_from_slice(&(part_len - 2).to_le_bytes());
    let crc_len = usize::from(u16::from_le_bytes([image[fe + 10], image[fe + 11]]));
    retag(&mut image, fe, 16 + crc_len);

    // Refused, and the rest written.
    let scratch = Scratch::new();
    let summary = extract(&image, &scratch.out(), &options_skip()).unwrap();
    let large = summary
        .skipped
        .iter()
        .find(|e| e.name.as_deref() == Some(&b"dir/sub/large"[..]))
        .unwrap();
    assert!(matches!(large.kind, ErrorKind::Udf(_)), "{large}");
    assert!(!scratch.out().join("dir/sub/large").exists());
    assert!(scratch.out().join("dir/medium").is_file());
    // Not skipped, it stops before anything is written.
    let scratch = Scratch::new();
    let e = extract(
        &image,
        &scratch.out(),
        &options(|o| o.links = Links::AsFile),
    )
    .unwrap_err();
    assert!(matches!(e.kind, ErrorKind::Udf(_)), "{e}");
    assert_eq!(e.name.as_deref(), Some(&b"dir/sub/large"[..]));
    assert!(
        listing(scratch.path()).is_empty(),
        "{:?}",
        listing(scratch.path())
    );
}

fn options_skip() -> Options {
    options(|o| {
        o.links = Links::AsFile;
        o.on_refused = OnRefused::Skip;
    })
}

/// Whether a descriptor with tag `id` starts at `at`.
fn tagged(image: &[u8], at: usize, id: [u8; 2]) -> bool {
    image[at..at + 2] == id
        && (0..16)
            .filter(|&i| i != 4)
            .fold(0u8, |s, i| s.wrapping_add(image[at + i]))
            == image[at + 4]
}

/// Recomputes the tag of the descriptor at `at`, `len` bytes long.
fn retag(image: &mut [u8], at: usize, len: usize) {
    let crc_len = len - 16;
    let mut crc: u16 = 0;
    for &b in &image[at + 16..at + len] {
        crc ^= u16::from(b) << 8;
        for _ in 0..8 {
            crc = if crc & 0x8000 != 0 {
                (crc << 1) ^ 0x1021
            } else {
                crc << 1
            };
        }
    }
    image[at + 8..at + 10].copy_from_slice(&crc.to_le_bytes());
    image[at + 10..at + 12].copy_from_slice(&(crc_len as u16).to_le_bytes());
    let sum = (0..16)
        .filter(|&i| i != 4)
        .fold(0u8, |s, i| s.wrapping_add(image[at + i]));
    image[at + 4] = sum;
}

#[test]
fn a_directory_named_twice_is_refused() {
    // dir/sub's FID made to name the root directory: a loop.
    let (mut image, _) = image("mkudffs-hd-0201");
    let fsd = (0..image.len() / 512)
        .map(|s| s * 512)
        .find(|&at| tagged(&image, at, [0, 1]))
        .unwrap();
    let root_lb: [u8; 4] = image[fsd + 404..fsd + 408].try_into().unwrap();
    // The FID of "sub": its tag, its name's length, and the name after its
    // implementation use.
    let name = b"\x08sub";
    let fid = (0..image.len() - 64)
        .step_by(4)
        .find(|&at| {
            let l_iu = usize::from(u16::from_le_bytes([image[at + 36], image[at + 37]]));
            tagged(&image, at, [1, 1])
                && image[at + 19] == 4
                && image.get(at + 38 + l_iu..at + 42 + l_iu) == Some(name)
        })
        .unwrap();
    let l_iu = usize::from(u16::from_le_bytes([image[fid + 36], image[fid + 37]]));
    image[fid + 24..fid + 28].copy_from_slice(&root_lb);
    let len = (38 + l_iu + name.len() + 3) & !3;
    retag(&mut image, fid, len);
    // The directory's FIDs are in its node, whose tag covers them too.
    let node = fid - fid % 512;
    if tagged(&image, node, [5, 1]) || tagged(&image, node, [10, 1]) {
        let crc_len = usize::from(u16::from_le_bytes([image[node + 10], image[node + 11]]));
        retag(&mut image, node, 16 + crc_len);
    }
    let scratch = Scratch::new();
    let e = extract(
        &image,
        &scratch.out(),
        &options(|o| o.links = Links::AsFile),
    )
    .unwrap_err();
    assert!(matches!(e.kind, ErrorKind::DirectoryAgain), "{e}");
    assert_eq!(e.name.as_deref(), Some(&b"dir/sub"[..]));
    let scratch = Scratch::new();
    let summary = extract(&image, &scratch.out(), &options_skip()).unwrap();
    assert!(
        summary
            .skipped
            .iter()
            .any(|e| matches!(e.kind, ErrorKind::DirectoryAgain))
    );
    assert!(scratch.out().join("dir/medium").is_file());
    assert!(!scratch.out().join("dir/sub").exists());
}

/// The options of these tests: names checked by every system's rules, as Windows
/// and a case-insensitive file system have them, wherever the tests run.
fn portable() -> hivepack::extract::Options {
    let mut options = hivepack::extract::Options::default();
    options.name_rules = hivepack::extract::NameRules::Portable;
    options
}
