//! Extracting a SquashFS image with `Options::threads`: files written several
//! at once, each by a thread reading the image through caches of its own,
//! and the blocks of the files still written decoded ahead by the threads
//! with nothing left to take. What is written, the summary, what
//! `Options::on_written` is told and what `Options::progress` reaches are the
//! same as with one thread, over `testdata/squashfs`'s images (every
//! compressor, LZO among them), the large ones mksquashfs makes
//! (`squashfs-images`: holes, hard links, a directory of 2,000 entries, a tree
//! 120 deep, blocks of 4 KiB to 1 MiB), KeeWeb's snap and appimagetool's
//! AppImage (`squashfs-real`), when fetched; with entries picked and refused;
//! and damaged blocks are reported the same. Cancelling, the time limit and a
//! memory limit or budget stop it, or lower the threads, as they do with one.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "threads_support/mod.rs"]
mod threads_support;

#[path = "extract_support/mod.rs"]
mod support;

use std::collections::{BTreeSet, HashMap, HashSet};
use std::io::{Cursor, Read, Seek};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use hivepack::Threads;
use hivepack::extract::{
    Cancel, Error, ErrorKind, Links, OnDamaged, OnRefused, Options, Progress, Summary, Written,
    extract_squashfs,
};
use hivepack::squashfs::Squashfs;
use support::{Scratch, listing, options};

/// One thread, two, eight, and as many as the machine runs.
fn every_threads() -> Vec<Threads> {
    threads_support::chosen([Threads::One, Threads::of(2), Threads::of(8), Threads::Auto])
}

fn committed(name: &str) -> Vec<u8> {
    std::fs::read(support::repository().join("testdata/squashfs").join(name)).unwrap()
}

/// The set `name` of the test data, if it was fetched.
fn fetched(name: &str) -> Option<PathBuf> {
    let set = support::testdata().join(name);
    if set.join(".complete").exists() {
        return Some(set);
    }
    assert!(!support::required("generated"), "{name} is missing");
    eprintln!("skipping: {name} is not there");
    None
}

/// What is under `dir`: each path, the length and a hash of what it holds or
/// leads to, its mode and time on Unix, and, for a second name of a file, the
/// first.
fn contents(dir: &Path) -> Vec<String> {
    let mut first_name: HashMap<(u64, u64), String> = HashMap::new();
    listing(dir)
        .into_iter()
        .map(|path| {
            let at = dir.join(&path);
            let metadata = at.symlink_metadata().unwrap();
            let data = if metadata.is_symlink() {
                std::fs::read_link(&at)
                    .unwrap()
                    .to_string_lossy()
                    .into_owned()
                    .into_bytes()
            } else if metadata.is_dir() {
                Vec::new()
            } else {
                std::fs::read(&at).unwrap()
            };
            // FNV-1a.
            let hash = data.iter().fold(0xcbf2_9ce4_8422_2325u64, |h, &b| {
                (h ^ u64::from(b)).wrapping_mul(0x100_0000_01b3)
            });
            #[cfg(unix)]
            let (mode, time, same) = {
                use std::os::unix::fs::MetadataExt;
                // A link's time is the system's; what has none from the
                // image has the time it was written at, which differs from
                // one run to the next.
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs() as i64;
                let time = match metadata.mtime() {
                    _ if metadata.is_symlink() => 0,
                    time if (now - time).abs() < 24 * 3600 => -1,
                    time => time,
                };
                let same = if metadata.is_file() {
                    first_name
                        .entry((metadata.dev(), metadata.ino()))
                        .or_insert_with(|| path.clone())
                        .clone()
                } else {
                    String::new()
                };
                (metadata.mode(), time, same)
            };
            #[cfg(not(unix))]
            let (mode, time, same) = (0, 0, {
                let _ = &mut first_name;
                String::new()
            });
            format!("{path} {} {hash:x} {mode:o} {time} {same}", data.len())
        })
        .collect()
}

/// What a summary says, to compare.
fn told(summary: &Summary) -> String {
    let damaged: Vec<_> = summary
        .damaged
        .iter()
        .map(|d| (d.error.index, format!("{:?}", d.error.kind), d.kept))
        .collect();
    let skipped: Vec<_> = summary.skipped.iter().map(|e| e.to_string()).collect();
    format!(
        "{} files, {} directories, {} links, {} bytes, skipped {skipped:?}, renamed {}, damaged {damaged:?}, owners left {}",
        summary.files,
        summary.directories,
        summary.links,
        summary.bytes,
        summary.renamed.len(),
        summary.owners_left,
    )
}

/// An image, to open each time.
enum Image<'a> {
    Bytes(&'a [u8]),
    /// A file, from where its image starts, as in an AppImage.
    File(&'a Path, u64),
}

impl Image<'_> {
    fn extract(&self, out: &Path, options: &Options) -> Result<Summary, Error> {
        match *self {
            Image::Bytes(bytes) => {
                let mut fs = Squashfs::open(Cursor::new(bytes)).unwrap();
                extract_squashfs(&mut fs, out, options)
            }
            Image::File(path, offset) => {
                let mut fs = Squashfs::open_at(std::fs::File::open(path).unwrap(), offset).unwrap();
                extract_squashfs(&mut fs, out, options)
            }
        }
    }
}

/// What an extraction gave: its summary, the files, what `on_written` was
/// told, and whether more than one thread told `progress`.
struct Found {
    summary: String,
    files: Vec<String>,
    written: BTreeSet<String>,
    reporting: usize,
}

/// Extracts `image` with `threads` and `change`'s options, and checks that
/// `progress` never went back and reached its totals, and that `on_written`
/// was told each entry once.
fn extract_with(
    image: &Image<'_>,
    threads: Threads,
    change: &dyn Fn(&mut Options),
) -> Result<Found, Error> {
    let scratch = Scratch::new();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let record = Arc::clone(&seen);
    let written = Arc::new(Mutex::new(Vec::new()));
    let tell = Arc::clone(&written);
    let options = options(|o| {
        o.threads = threads;
        o.on_refused = OnRefused::Skip;
        o.progress = Some(Arc::new(move |progress: &Progress| {
            record
                .lock()
                .unwrap()
                .push((*progress, std::thread::current().id()));
        }));
        o.on_written = Some(Arc::new(move |written: &Written<'_>| {
            tell.lock()
                .unwrap()
                .push(format!("{} {:?}", written.path.join("/"), written.kind));
        }));
        change(o);
    });
    let summary = image.extract(&scratch.out(), &options)?;
    let seen = seen.lock().unwrap();
    for pair in seen.windows(2) {
        let (before, after) = (pair[0].0, pair[1].0);
        assert!(before.entries <= after.entries && before.bytes <= after.bytes);
    }
    if let Some(&(last, _)) = seen.last() {
        // A damaged file left out, or kept in part, is not all written.
        if summary.damaged.is_empty() {
            assert_eq!(
                (last.entries, last.bytes),
                (last.total_entries, last.total_bytes),
                "{threads:?}"
            );
            assert_eq!(last.bytes, summary.bytes);
        }
        assert!(last.bytes <= last.total_bytes);
    }
    let written = written.lock().unwrap();
    let told_once: BTreeSet<String> = written.iter().cloned().collect();
    assert_eq!(told_once.len(), written.len(), "told twice");
    Ok(Found {
        summary: told(&summary),
        files: contents(&scratch.out()),
        written: told_once,
        reporting: seen.iter().map(|(_, id)| *id).collect::<HashSet<_>>().len(),
    })
}

/// Extracts `image` with every count of threads and `change`'s options, and
/// checks that each gives what one thread does: the summary, then the files.
fn the_same(name: &str, image: &Image<'_>, change: &dyn Fn(&mut Options)) -> Found {
    let mut first: Option<Found> = None;
    for threads in every_threads() {
        let found = extract_with(image, threads, change)
            .unwrap_or_else(|e| panic!("{name} with {threads:?}: {e}"));
        if threads == Threads::One {
            assert_eq!(found.reporting, 1, "{name}");
        }
        match &first {
            None => first = Some(found),
            Some(first) => {
                assert_eq!(first.summary, found.summary, "{name} with {threads:?}");
                assert_eq!(first.files, found.files, "{name} with {threads:?}");
                assert_eq!(first.written, found.written, "{name} with {threads:?}");
            }
        }
    }
    first.unwrap()
}

/// The ways an image is extracted: links as files and, on Unix, inside;
/// entries picked; links refused, left out.
fn every_way(name: &str, image: &Image<'_>, inside: bool) {
    let found = the_same(name, image, &|o| o.links = Links::AsFile);
    assert!(found.files.len() > 1, "{name}");
    if inside {
        the_same(name, image, &|o| o.links = Links::Inside);
    }
    // Every other file picked, by its name's length.
    the_same(name, image, &|o| {
        o.links = if inside { Links::Inside } else { Links::AsFile };
        o.select = Some(Arc::new(|path: &[String]| {
            path.join("/").len().is_multiple_of(2)
        }));
    });
    // Links refused, and left out.
    let found = the_same(name, image, &|o| o.links = Links::Refuse);
    assert!(found.summary.contains("skipped"), "{name}");
}

#[test]
fn committed_images_are_the_same() {
    for name in ["gzip", "lzma", "lzo", "xz", "lz4", "zstd", "uncompressed"] {
        let image = committed(&format!("{name}.sqfs"));
        every_way(name, &Image::Bytes(&image), cfg!(unix));
    }
}

#[test]
fn large_images_are_the_same() {
    let Some(images) = fetched("squashfs-images") else {
        return;
    };
    // Links inside on Linux only: the full tree has a link of 4,000 bytes,
    // and macOS makes none longer than 1,023.
    let inside = cfg!(target_os = "linux");
    let names: &[&str] = if threads_support::emulated() {
        &["gzip", "zstd-b4k"]
    } else {
        &[
            "gzip",
            "lzma",
            "lzo",
            "xz",
            "lz4",
            "zstd",
            "gzip-b4k",
            "zstd-b4k",
            "gzip-b1m",
            "zstd-b1m",
            "gzip-uncompressed",
            "no-fragments",
            "tailends",
            "no-sparse",
            "no-duplicates",
            "no-hardlinks",
        ]
    };
    for name in names {
        let image = std::fs::read(images.join(format!("{name}.sqfs"))).unwrap();
        let found = the_same(name, &Image::Bytes(&image), &|o| o.links = Links::AsFile);
        // The full tree: 2,000 entries in a directory, a tree 120 deep, and
        // hard links.
        assert!(found.files.len() > 2100, "{name}: {}", found.files.len());
        assert!(
            found.files.iter().any(|f| f.contains("/d120/bottom")),
            "{name}"
        );
        if inside {
            let found = the_same(name, &Image::Bytes(&image), &|o| o.links = Links::Inside);
            #[cfg(unix)]
            assert!(
                *name == "no-hardlinks"
                    || found
                        .files
                        .iter()
                        .any(|f| f.starts_with("files/hardlink-a ")
                            && f.ends_with(" dirs/hardlink-c")),
                "{name}"
            );
            let _ = found;
        }
    }
    // The file of 9 MiB in blocks of 4 KiB is read through its block index,
    // which leads where its block sizes do: written in threads.
    if !threads_support::emulated() {
        let image = std::fs::read(images.join("zstd-b4k.sqfs")).unwrap();
        let eight = extract_with(&Image::Bytes(&image), Threads::of(8), &|o| {
            o.links = Links::AsFile;
        })
        .unwrap();
        assert!(eight.reporting > 1, "{}", eight.reporting);
    }
    // Each way, on two.
    for name in ["xz", "zstd-b4k"] {
        let image = std::fs::read(images.join(format!("{name}.sqfs"))).unwrap();
        every_way(name, &Image::Bytes(&image), inside);
    }
}

#[test]
fn real_files_are_the_same() {
    let Some(real) = fetched("squashfs-real") else {
        return;
    };
    // Creating links takes a privilege on Windows.
    let links = if cfg!(unix) {
        Links::Inside
    } else {
        Links::AsFile
    };
    let snap = real.join("KeeWeb-1.18.7.linux.snap");
    let found = the_same("KeeWeb snap", &Image::File(&snap, 0), &|o| {
        o.links = links;
    });
    // 244 files, the largest of 137 MB: eight threads all take some, and
    // decode its blocks ahead.
    assert!(found.files.len() > 300, "{}", found.files.len());
    if !threads_support::emulated() {
        let eight = extract_with(&Image::File(&snap, 0), Threads::of(8), &|o| {
            o.links = links;
        })
        .unwrap();
        assert!(eight.reporting > 1, "{}", eight.reporting);
    }

    let appimage = real.join("appimagetool-x86_64.AppImage");
    let offset = {
        let file = std::fs::File::open(&appimage).unwrap();
        let fs = hivepack::appimage::open_squashfs(file).unwrap();
        fs.offset()
    };
    assert_eq!(offset, 944_632);
    the_same("appimagetool", &Image::File(&appimage, offset), &|o| {
        o.links = links;
    });
}

/// `image` with a byte changed in each data block of the files named, at
/// their first block's place: their data does not decompress.
fn damaged(image: &[u8], names: &[&[u8]]) -> Vec<u8> {
    let mut fs = Squashfs::open(Cursor::new(image)).unwrap();
    let root = fs.root().unwrap();
    let mut out = image.to_vec();
    for name in names {
        let (_, inode) = fs.lookup_path(&root, name).unwrap().unwrap();
        let at = inode.start_block() as usize + 8;
        out[at] ^= 0x55;
    }
    out
}

/// Damaged blocks are reported the same, whatever the threads: asked about
/// and gone on from, in the image's order; or stopping the extraction with
/// the error of one, the first with one thread, the damaged files not left.
fn damage_is_the_same(name: &str, image: &[u8], bad: &[&str]) {
    let names: Vec<&[u8]> = bad.iter().map(|n| n.as_bytes()).collect();
    let image = damaged(image, &names);
    let image = Image::Bytes(&image);
    for how in [OnDamaged::Skip, OnDamaged::Keep] {
        let asked = Arc::new(Mutex::new(Vec::new()));
        let found = the_same(name, &image, &|o| {
            o.links = Links::AsFile;
            let record = Arc::clone(&asked);
            o.on_damaged = Some(Arc::new(move |error: &Error| {
                record.lock().unwrap().push(error.name.clone().unwrap());
                how
            }));
        });
        // Asked about each, once for each count of threads.
        let mut asked = asked.lock().unwrap().clone();
        asked.sort();
        asked.dedup();
        let mut expected: Vec<Vec<u8>> = names.iter().map(|n| n.to_vec()).collect();
        expected.sort();
        assert_eq!(asked, expected, "{name}");
        assert!(
            found.summary.contains("Squashfs"),
            "{name}: {}",
            found.summary
        );
    }

    let mut indexes = Vec::new();
    for threads in every_threads() {
        let scratch = Scratch::new();
        let options = options(|o| {
            o.threads = threads;
            o.links = Links::AsFile;
            o.on_refused = OnRefused::Skip;
        });
        let error = image.extract(&scratch.out(), &options).unwrap_err();
        assert!(
            matches!(error.kind, ErrorKind::Squashfs(_)) && error.kind.is_damage(),
            "{name}: {error}"
        );
        let failed = String::from_utf8(error.name.clone().unwrap()).unwrap();
        assert!(bad.contains(&failed.as_str()), "{name}: {error}");
        indexes.push((threads, failed));
        for bad in bad {
            assert!(!scratch.out().join(bad).exists(), "{name}: {bad}");
        }
    }
    // One thread stops at the first damaged file it writes.
    assert_eq!(indexes[0].0, Threads::One);
}

#[test]
fn damaged_blocks_are_the_same() {
    damage_is_the_same("gzip", &committed("gzip.sqfs"), &["blocks.txt"]);
    let Some(images) = fetched("squashfs-images") else {
        return;
    };
    // Blocks of 4 KiB: the file of 9 MiB has 2,304 of them, read through its
    // block index, and decoded ahead by the threads with nothing else to do.
    let image = std::fs::read(images.join("gzip-b4k.sqfs")).unwrap();
    damage_is_the_same(
        "gzip-b4k",
        &image,
        &["files/hole-3m", "files/numbered-9m", "files/x86-code"],
    );
    // A block in the middle of the file of 9 MiB.
    let mut fs = Squashfs::open(Cursor::new(&image[..])).unwrap();
    let root = fs.root().unwrap();
    let (_, inode) = fs
        .lookup_path(&root, b"files/numbered-9m")
        .unwrap()
        .unwrap();
    let start = inode.start_block() as usize;
    let mut middle = image.clone();
    // Its blocks follow each other, some hundreds of bytes each compressed.
    middle[start + 200_000] ^= 0x55;
    let middle = Image::Bytes(&middle);
    for how in [OnDamaged::Skip, OnDamaged::Keep] {
        let found = the_same("gzip-b4k, a block in the middle", &middle, &|o| {
            o.links = Links::AsFile;
            o.on_damaged = Some(Arc::new(move |_: &Error| how));
        });
        assert!(found.summary.contains("Squashfs"), "{}", found.summary);
    }
}

/// Where the field `field` bytes into the inode `id` is in an image whose
/// metadata is not compressed, each block of it 8 KiB after its header.
fn raw_inode_field(table: usize, id: u64, field: usize) -> usize {
    let mut block = (id >> 16) as usize;
    let mut offset = (id & 0xffff) as usize + field;
    while offset >= 8192 {
        block += 2 + 8192;
        offset -= 8192;
    }
    table + block + 2 + offset
}

fn le32(image: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(image[at..at + 4].try_into().unwrap())
}

/// An image whose files would not read the same through caches of their own
/// is written on one thread: the same as one thread writes, whatever the
/// threads.
#[test]
fn a_place_read_with_two_sizes_is_the_same() {
    let Some(images) = fetched("squashfs-images") else {
        return;
    };
    // Nothing compressed, metadata too, so that the inodes can be changed
    // in place: every block of 128 KiB stored.
    let mut image = std::fs::read(images.join("gzip-uncompressed.sqfs")).unwrap();
    let mut fs = Squashfs::open(Cursor::new(image.clone())).unwrap();
    let root = fs.root().unwrap();
    let table = fs.superblock().inode_table_start as usize;
    let block_size = fs.superblock().block_size;
    let (Some(mib), _) = fs.lookup_path(&root, b"files/mib-plus-3").unwrap().unwrap() else {
        panic!()
    };
    let (Some(mixed), _) = fs.lookup_path(&root, b"files/mixed-3m").unwrap().unwrap() else {
        panic!()
    };
    // Basic file inodes: the first block at 16, the fragment at 20, the
    // size at 28, the block sizes from 32. mib-plus-3 has no fragment: its
    // last 3 bytes are a block of their own.
    let header =
        |image: &[u8], id: u64, n: usize| le32(image, raw_inode_field(table, id, 32 + 4 * n));
    assert_eq!(le32(&image, raw_inode_field(table, mib, 20)), u32::MAX);
    let size = le32(&image, raw_inode_field(table, mib, 28));
    let blocks = size.div_ceil(block_size) as usize;
    let mut last = u64::from(le32(&image, raw_inode_field(table, mib, 16)));
    for n in 0..blocks - 1 {
        last += u64::from(header(&image, mib, n) & !(1 << 24));
    }
    assert_eq!(header(&image, mib, blocks - 1), (1 << 24) | 3);
    // mixed-3m, read right after mib-plus-3, made to start where its last
    // block is, read as 64 KiB: one thread finds the block of 3 bytes in its
    // cache, a thread with caches of its own would read 64 KiB.
    let at = raw_inode_field(table, mixed, 16);
    image[at..at + 4].copy_from_slice(&(last as u32).to_le_bytes());
    let at = raw_inode_field(table, mixed, 32);
    image[at..at + 4].copy_from_slice(&((1u32 << 24) | 65536).to_le_bytes());

    let image = Image::Bytes(&image);
    // Kept, mixed-3m holds what was read before its read failed.
    for how in [OnDamaged::Keep, OnDamaged::Skip] {
        let change = move |o: &mut Options| {
            o.links = Links::AsFile;
            o.on_damaged = Some(Arc::new(move |_: &Error| how));
        };
        let found = the_same("one place, two sizes", &image, &change);
        assert!(
            found
                .files
                .iter()
                .any(|f| f.starts_with("files/mib-plus-3 "))
        );
        // Written on one thread.
        if !threads_support::emulated() {
            let eight = extract_with(&image, Threads::of(8), &change).unwrap();

            assert_eq!(eight.reporting, 1);
        }
    }
}

#[test]
fn cancelling_stops_it() {
    let images = fetched("squashfs-images");
    let image = match &images {
        Some(images) => std::fs::read(images.join("gzip-b4k.sqfs")).unwrap(),
        None => committed("gzip.sqfs"),
    };
    let image = Image::Bytes(&image);
    for threads in every_threads() {
        // Before anything is written.
        let scratch = Scratch::new();
        let cancel = Cancel::new();
        cancel.cancel();
        let o = options(|o| {
            o.threads = threads;
            o.cancel = Some(cancel);
        });
        let error = image.extract(&scratch.out(), &o).unwrap_err();
        assert!(matches!(error.kind, ErrorKind::Cancelled), "{error}");
        assert!(!scratch.out().exists());

        let scratch = Scratch::new();
        let o = options(|o| {
            o.threads = threads;
            o.time_limit = Some(Duration::ZERO);
        });
        let error = image.extract(&scratch.out(), &o).unwrap_err();
        assert!(matches!(error.kind, ErrorKind::TimeLimit), "{error}");
        assert!(!scratch.out().exists());

        if images.is_none() {
            continue;
        }
        // Once a megabyte is written: every thread stops, and what was cut
        // off is removed; what is left is whole.
        let scratch = Scratch::new();
        let cancel = Cancel::new();
        let token = cancel.clone();
        let o = options(|o| {
            o.threads = threads;
            o.links = Links::AsFile;
            o.on_refused = OnRefused::Skip;
            o.cancel = Some(cancel);
            o.progress = Some(Arc::new(move |progress: &Progress| {
                if progress.bytes > 1 << 20 {
                    token.cancel();
                }
            }));
        });
        let error = image.extract(&scratch.out(), &o).unwrap_err();
        assert!(matches!(error.kind, ErrorKind::Cancelled), "{error}");
        let Image::Bytes(bytes) = image else {
            unreachable!()
        };
        let mut fs = Squashfs::open(Cursor::new(bytes)).unwrap();
        let root = fs.root().unwrap();
        let mut left = 0;
        let mut total = 0u64;
        for path in listing(&scratch.out()) {
            let at = scratch.out().join(&path);
            if !at.symlink_metadata().unwrap().is_file() {
                continue;
            }
            let (_, inode) = fs.lookup_path(&root, path.as_bytes()).unwrap().unwrap();
            let mut data = Vec::new();
            fs.file(&inode).read_to_end(&mut data).unwrap();
            let written = std::fs::read(&at).unwrap();
            total += written.len() as u64;
            assert!(written == data, "{path} with {threads:?}");
            left += 1;
        }
        // Not all of it: 20 MB.
        assert!(
            total < 12 << 20,
            "{left} files, {total} bytes with {threads:?}"
        );
    }
}

#[test]
fn a_memory_limit_lowers_the_threads() {
    let image = committed("xz.sqfs");
    let image = Image::Bytes(&image);
    // Too little for two threads: one writes, as without threads.
    for limit in [0, 1 << 20, 64 << 20] {
        let found = extract_with(&image, Threads::of(8), &|o| {
            o.links = Links::AsFile;
            o.memory_limit = Some(limit);
        })
        .unwrap();
        let one = extract_with(&image, Threads::One, &|o| o.links = Links::AsFile).unwrap();
        assert_eq!(found.summary, one.summary);
        assert_eq!(found.files, one.files);
        if limit < 1 << 20 {
            assert_eq!(found.reporting, 1, "{limit}");
        }
    }
}

#[cfg(feature = "memory")]
#[test]
fn a_budget_is_held_and_given_back() {
    use hivepack::memory::Budget;
    let image = committed("zstd.sqfs");
    let image = Image::Bytes(&image);
    let budget = Budget::new(1 << 30);
    let held = Arc::new(Mutex::new(0u64));
    let during = Arc::clone(&held);
    let watched = budget.clone();
    let found = extract_with(&image, Threads::of(4), &|o| {
        o.links = Links::AsFile;
        o.memory_budget = Some(budget.clone());
        let during = Arc::clone(&during);
        let watched = watched.clone();
        o.progress = Some(Arc::new(move |_: &Progress| {
            let mut most = during.lock().unwrap();
            *most = (*most).max(watched.held());
        }));
    })
    .unwrap();
    assert!(*held.lock().unwrap() > 0);
    assert_eq!(budget.held(), 0);
    let one = extract_with(&image, Threads::One, &|o| o.links = Links::AsFile).unwrap();
    assert_eq!(found.files, one.files);

    // A budget with nothing left: one thread, holding nothing.
    let empty = Budget::new(0);
    let found = extract_with(&image, Threads::of(4), &|o| {
        o.links = Links::AsFile;
        o.memory_budget = Some(empty.clone());
    })
    .unwrap();
    assert_eq!(found.files, one.files);
    assert_eq!(empty.held(), 0);
}

/// The time to extract each image into a folder in memory (`/dev/shm`) with
/// one thread and with all, the best of five, and squashfs-tools'
/// squashfs-tools' `unsquashfs -p` of as many, when the `unsquashfs` set was
/// made (`scripts/testdata.py fetch --set unsquashfs`):
/// `cargo test --release -p hivepack --test extract_squashfs_threads speed -- --ignored --nocapture`.
#[test]
#[ignore = "measures; run on its own, in release"]
fn speed() {
    let root = PathBuf::from("/dev/shm").join(format!("hivepack-speed-{}", std::process::id()));
    let mut images: Vec<(String, PathBuf, u64)> = Vec::new();
    if let Some(real) = fetched("squashfs-real") {
        images.push((
            "KeeWeb 1.18.7's snap (xz)".into(),
            real.join("KeeWeb-1.18.7.linux.snap"),
            0,
        ));
        let appimage = real.join("appimagetool-x86_64.AppImage");
        let fs =
            hivepack::appimage::open_squashfs(std::fs::File::open(&appimage).unwrap()).unwrap();
        images.push((
            "appimagetool 1.9.1's AppImage (zstd)".into(),
            appimage,
            fs.offset(),
        ));
    }
    if let Some(generated) = fetched("squashfs-images") {
        for name in [
            "gzip",
            "lzma",
            "lzo",
            "xz",
            "lz4",
            "zstd",
            "zstd-b1m",
            "gzip-uncompressed",
        ] {
            images.push((
                format!("the full tree, {name}"),
                generated.join(format!("{name}.sqfs")),
                0,
            ));
        }
    }
    let all = Threads::Auto.count();
    let unsquashfs = Some(support::testdata().join("unsquashfs"))
        .filter(|set| set.join(".complete").exists())
        .map(|set| set.join("unsquashfs"));
    let best = |run: &dyn Fn(&Path)| {
        (0..5)
            .map(|_| {
                let _ = std::fs::remove_dir_all(&root);
                std::fs::create_dir_all(&root).unwrap();
                let out = root.join("out");
                let start = std::time::Instant::now();
                run(&out);
                start.elapsed().as_secs_f64()
            })
            .fold(f64::MAX, f64::min)
    };
    for (name, path, offset) in &images {
        let ours = |threads: Threads| {
            best(&|out: &Path| {
                let mut file = std::fs::File::open(path).unwrap();
                file.rewind().unwrap();
                let mut fs = Squashfs::open_at(file, *offset).unwrap();
                let o = options(|o| {
                    o.threads = threads;
                    o.links = Links::Inside;
                    o.on_refused = OnRefused::Skip;
                });
                extract_squashfs(&mut fs, out, &o).unwrap();
            })
        };
        let one = ours(Threads::One);
        let every = ours(Threads::Auto);
        let theirs = |p: u32| {
            unsquashfs.as_ref().map(|unsquashfs| {
                best(&|out: &Path| {
                    let status = std::process::Command::new(unsquashfs)
                        .args(["-q", "-n", "-no-xattrs", "-p", &p.to_string()])
                        .args(["-o", &offset.to_string(), "-d"])
                        .arg(out)
                        .arg(path)
                        .stdout(std::process::Stdio::null())
                        .stderr(std::process::Stdio::null())
                        .status()
                        .unwrap();
                    let _ = status;
                })
            })
        };
        let (theirs_one, theirs_all) = (theirs(1), theirs(all));
        println!(
            "| {name} | {one:.3} s | {every:.3} s ({:.1}×) | {} | {} |",
            one / every,
            theirs_one.map_or("-".into(), |t| format!("{t:.3} s")),
            theirs_all.map_or("-".into(), |t| format!("{t:.3} s")),
        );
    }
    let _ = std::fs::remove_dir_all(&root);
}
