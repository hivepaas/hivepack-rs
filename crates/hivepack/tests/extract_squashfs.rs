//! Extracting SquashFS images that hivepack::squashfs opens: the images of
//! `testdata/squashfs` and, when fetched, the large ones mksquashfs makes
//! (`squashfs-images`) and a snap (`squashfs-real`), extracted as the port
//! reads them, which `tests/squashfs_oracle.rs` checks against squashfuse
//! (each file's data the same, each link's target, the entries refused for
//! their reason); and images changed to attack: a file's data past the
//! image, a directory met again. Nothing may be left outside the
//! destination, and nothing at all when the checks before writing stop it.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "extract_support/mod.rs"]
mod support;

use std::collections::HashMap;
use std::io::{Cursor, Read};
use std::path::Path;

use hivepack::extract::{ErrorKind, Links, OnRefused, Options, Summary, extract_squashfs};
use hivepack::squashfs::{Squashfs, Step};
use support::{Scratch, listing, options};

fn committed(name: &str) -> Vec<u8> {
    std::fs::read(support::repository().join("testdata/squashfs").join(name)).unwrap()
}

fn extract(
    image: &[u8],
    out: &Path,
    options: &Options,
) -> Result<Summary, hivepack::extract::Error> {
    let mut fs = Squashfs::open(Cursor::new(image.to_vec())).unwrap();
    extract_squashfs(&mut fs, out, options)
}

/// What the port reads of every entry: path, the inode's id, what it is
/// (`d`, `f`, `l` or another), and its data or link target.
fn entries(image: &[u8]) -> Vec<(Vec<u8>, u64, char, Vec<u8>)> {
    let mut fs = Squashfs::open(Cursor::new(image.to_vec())).unwrap();
    let root = fs.root().unwrap();
    let mut walk = fs.traverse(&root).unwrap();
    let mut out = Vec::new();
    while let Some(step) = walk.next(&mut fs).unwrap() {
        let Step::Entry { path, entry } = step else {
            continue;
        };
        let inode = fs.inode(entry.inode).unwrap();
        let (kind, data) = if inode.is_dir() {
            ('d', Vec::new())
        } else if inode.is_file() {
            let mut data = Vec::new();
            fs.file(&inode).read_to_end(&mut data).unwrap();
            ('f', data)
        } else if inode.is_symlink() {
            ('l', fs.read_link(&inode).unwrap())
        } else {
            ('s', Vec::new())
        };
        out.push((path, entry.inode, kind, data));
    }
    out
}

/// Extracts `image` with links as files and, on Unix, inside, entries
/// refused left out, and checks every entry against what the port reads.
fn extracts_as_read(name: &str, image: &[u8]) {
    extracts_as_read_with(name, image, cfg!(unix));
}

/// [`extracts_as_read`], with links inside only if `inside`.
fn extracts_as_read_with(name: &str, image: &[u8], inside: bool) {
    let choices: &[Links] = if inside {
        &[Links::AsFile, Links::Inside]
    } else {
        &[Links::AsFile]
    };
    let read = entries(image);
    for &links in choices {
        let scratch = Scratch::new();
        let out = scratch.out();
        let options = options(|o| {
            o.links = links;
            o.on_refused = OnRefused::Skip;
        });
        let summary = extract(image, &out, &options).unwrap_or_else(|e| panic!("{name}: {e}"));
        for path in listing(scratch.path()) {
            assert!(path.starts_with("out/") || path == "out/", "{name}: {path}");
        }
        let skipped: HashMap<Vec<u8>, &ErrorKind> = summary
            .skipped
            .iter()
            .map(|e| (e.name.clone().unwrap_or_default(), &e.kind))
            .collect();
        let mut first_of: HashMap<u64, &Vec<u8>> = HashMap::new();
        let mut files = 0;
        for (path, inode, kind, data) in &read {
            let shown = String::from_utf8_lossy(path).into_owned();
            let at = out.join(std::str::from_utf8(path).unwrap());
            if let Some(why) = skipped.get(path) {
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
                'f' => {
                    assert!(std::fs::read(&at).unwrap() == *data, "{name}: {shown}");
                    files += 1;
                    // A second name for an inode is a hard link to the
                    // first (copied with links as files).
                    #[cfg(unix)]
                    if let Some(first) = first_of.get(inode).filter(|_| links == Links::Inside) {
                        use std::os::unix::fs::MetadataExt;
                        let a = std::fs::metadata(out.join(std::str::from_utf8(first).unwrap()));
                        assert_eq!(
                            a.unwrap().ino(),
                            at.metadata().unwrap().ino(),
                            "{name}: {shown}"
                        );
                    }
                    first_of.entry(*inode).or_insert(path);
                }
                'l' if links == Links::AsFile => {
                    assert_eq!(std::fs::read(&at).unwrap(), *data, "{name}: {shown}");
                    files += 1;
                }
                'l' => {
                    let target = std::fs::read_link(&at).unwrap();
                    assert_eq!(
                        target.to_str().unwrap().as_bytes(),
                        &data[..],
                        "{name}: {shown}"
                    );
                }
                _ => panic!("{name}: {shown}: a device, FIFO or socket not refused"),
            }
        }
        assert_eq!(summary.files, files, "{name}");
    }
}

#[test]
fn committed_images_extract_as_read() {
    for name in ["gzip", "lzma", "lzo", "xz", "lz4", "zstd", "uncompressed"] {
        let image = committed(&format!("{name}.sqfs"));
        extracts_as_read(name, &image);
    }
}

#[test]
fn large_images_extract_as_read() {
    let cache = support::testdata();
    let images = cache.join("squashfs-images");
    if !images.join(".complete").exists() {
        assert!(
            !support::required("generated"),
            "squashfs-images is missing"
        );
        eprintln!("skipping: squashfs-images is not there");
        return;
    }
    // Every inode type, block sizes, holes, a tree 120 deep, 2,000 entries
    // in a directory, UTF-8 and long names.
    // Links inside on Linux only: the full tree has a link of 4,000 bytes,
    // and macOS makes none longer than 1,023 (ENAMETOOLONG).
    for name in ["gzip", "xz", "zstd-b4k", "no-sparse"] {
        let image = std::fs::read(images.join(format!("{name}.sqfs"))).unwrap();
        extracts_as_read_with(name, &image, cfg!(target_os = "linux"));
    }
    let real = cache.join("squashfs-real/KeeWeb-1.18.7.linux.snap");
    if real.exists() {
        extracts_as_read("KeeWeb snap", &std::fs::read(real).unwrap());
    }
}

/// The places of the uncompressed image's root listing: its first entry.
fn first_root_entry(image: &[u8]) -> usize {
    let mut fs = Squashfs::open(Cursor::new(image.to_vec())).unwrap();
    let root = fs.root().unwrap();
    let (start, offset, ..) = root.dir_info();
    assert_eq!(start, 0);
    let directory_table = fs.superblock().directory_table_start as usize;
    // The metadata block's header, the listing's header, then the entry.
    directory_table + 2 + usize::from(offset) + 12
}

#[test]
fn a_directory_met_again_is_refused() {
    // The root's first entry, blocks.txt, made to name the root itself.
    let mut image = committed("uncompressed.sqfs");
    let at = first_root_entry(&image);
    let root_id = {
        let fs = Squashfs::open(Cursor::new(image.clone())).unwrap();
        fs.root_id()
    };
    assert_eq!(root_id >> 16, 0);
    image[at..at + 2].copy_from_slice(&(root_id as u16).to_le_bytes());

    let scratch = Scratch::new();
    let summary = extract(
        &image,
        &scratch.out(),
        &options(|o| {
            o.links = Links::AsFile;
            o.on_refused = OnRefused::Skip;
        }),
    )
    .unwrap();
    let refused = summary
        .skipped
        .iter()
        .find(|e| e.name.as_deref() == Some(&b"blocks.txt"[..]))
        .unwrap();
    assert!(
        matches!(refused.kind, ErrorKind::DirectoryAgain),
        "{refused}"
    );
    assert!(scratch.out().join("dir/inner.txt").is_file());
    assert!(!scratch.out().join("blocks.txt").exists());

    // Not skipped, it stops before anything is written.
    let scratch = Scratch::new();
    let e = extract(
        &image,
        &scratch.out(),
        &options(|o| o.links = Links::AsFile),
    )
    .unwrap_err();
    assert!(matches!(e.kind, ErrorKind::DirectoryAgain), "{e}");
    assert!(
        listing(scratch.path()).is_empty(),
        "{:?}",
        listing(scratch.path())
    );
}

#[test]
fn data_not_on_the_image_stops_before_writing() {
    // blocks.txt's first block moved past the image's end, as an image cut
    // short has it.
    let mut image = committed("uncompressed.sqfs");
    let mut fs = Squashfs::open(Cursor::new(image.clone())).unwrap();
    let root = fs.root().unwrap();
    let entry = fs.lookup(&root, b"blocks.txt").unwrap().unwrap();
    let inode = fs.inode(entry.inode).unwrap();
    assert!(inode.is_file() && inode.start_block() < 1 << 20);
    // The basic file inode: its start_block, 16 bytes in, in the raw
    // inode table, after the metadata block's header.
    let table = fs.superblock().inode_table_start as usize;
    let at = table + 2 + (entry.inode & 0xffff) as usize + 16;
    assert_eq!(
        u32::from_le_bytes(image[at..at + 4].try_into().unwrap()),
        inode.start_block() as u32
    );
    let past = image.len() as u32;
    image[at..at + 4].copy_from_slice(&past.to_le_bytes());

    let scratch = Scratch::new();
    let summary = extract(
        &image,
        &scratch.out(),
        &options(|o| {
            o.links = Links::AsFile;
            o.on_refused = OnRefused::Skip;
        }),
    )
    .unwrap();
    let refused = summary
        .skipped
        .iter()
        .find(|e| e.name.as_deref() == Some(&b"blocks.txt"[..]))
        .unwrap();
    assert!(matches!(refused.kind, ErrorKind::Squashfs(_)), "{refused}");
    assert!(scratch.out().join("hello.txt").is_file());

    let scratch = Scratch::new();
    let e = extract(
        &image,
        &scratch.out(),
        &options(|o| o.links = Links::AsFile),
    )
    .unwrap_err();
    assert!(matches!(e.kind, ErrorKind::Squashfs(_)), "{e}");
    assert_eq!(e.name.as_deref(), Some(&b"blocks.txt"[..]));
    assert!(
        listing(scratch.path()).is_empty(),
        "{:?}",
        listing(scratch.path())
    );
}

#[test]
fn a_block_that_does_not_decompress_is_damage() {
    // gzip.sqfs's blocks.txt, a byte of its first block's deflate data
    // changed: its data is on the image, and fails as it is written.
    let image = committed("gzip.sqfs");
    let mut fs = Squashfs::open(Cursor::new(image.clone())).unwrap();
    let root = fs.root().unwrap();
    let entry = fs.lookup(&root, b"blocks.txt").unwrap().unwrap();
    let inode = fs.inode(entry.inode).unwrap();
    let mut damaged = image.clone();
    let at = inode.start_block() as usize + 8;
    damaged[at] ^= 0x55;
    let mut fs = Squashfs::open(Cursor::new(damaged.clone())).unwrap();
    fs.check_data(&inode).unwrap();
    let skip = |o: &mut Options| {
        o.links = Links::AsFile;
        o.on_refused = OnRefused::Skip;
    };
    let scratch = Scratch::new();
    let e = extract(&damaged, &scratch.out(), &options(skip)).unwrap_err();
    assert!(matches!(e.kind, ErrorKind::Squashfs(_)), "{e}");
    assert!(e.kind.is_damage());
    assert!(!scratch.out().join("blocks.txt").exists());
    // Left out, the others are written.
    let scratch = Scratch::new();
    let summary = extract(
        &damaged,
        &scratch.out(),
        &options(|o| {
            skip(o);
            o.on_damaged = Some(std::sync::Arc::new(|_| hivepack::extract::OnDamaged::Skip));
        }),
    )
    .unwrap();
    assert_eq!(summary.damaged.len(), 1);
    assert!(!scratch.out().join("blocks.txt").exists());
    assert!(scratch.out().join("hello.txt").is_file());
}
