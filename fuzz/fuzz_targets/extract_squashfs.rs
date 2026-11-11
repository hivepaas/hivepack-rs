//! Extracts the input as a SquashFS image with hivepack::extract, as the
//! `extract_udf` target does a UDF volume: its first byte choosing the
//! options, the rest the image, into a scratch folder beside a file that
//! must stay as it was,
//! and cancelled after some progress if it says so. A panic is a bug, and
//! so is a file written outside the destination, a link that leads outside
//! it, a count of files the summary does not give, or a file left cut off:
//! the files left hold the bytes of the entries written in full, however
//! the extraction ends. A hard link's file counts once.
//! Half the time, by the input's length, with three threads, which write
//! files at once and decode their blocks ahead: then what is left is no more
//! than what was told written, as files other threads were writing when one
//! failed are removed; and, when it is not cancelled, what is written is
//! what one thread writes, and the summary the same, or both fail.
//! `crates/hivepack/tests/extract_squashfs.rs` has the cases made by hand.

#![no_main]

use std::io::Cursor;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use std::collections::HashSet;
use std::os::unix::fs::MetadataExt;

use hivepack::Threads;
use hivepack::extract::{
    Cancel, Links, Names, OnRefused, Options, Progress, Summary, extract_squashfs,
};
use hivepack::squashfs::Squashfs;
use libfuzzer_sys::fuzz_target;

/// The paths under `dir`: the files, and the links with their targets.
fn walk(dir: &Path, files: &mut Vec<PathBuf>, links: &mut Vec<(PathBuf, PathBuf)>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let Ok(metadata) = std::fs::symlink_metadata(&path) else {
            continue;
        };
        if metadata.is_symlink() {
            if let Ok(target) = std::fs::read_link(&path) {
                links.push((path, target));
            }
        } else if metadata.is_dir() {
            walk(&path, files, links);
        } else {
            files.push(path);
        }
    }
}

/// What is under `dir`, by path from it: each file's bytes and each link's
/// target.
fn tree(dir: &Path) -> Vec<(PathBuf, Vec<u8>)> {
    let (mut files, mut links) = (Vec::new(), Vec::new());
    walk(dir, &mut files, &mut links);
    let mut out: Vec<(PathBuf, Vec<u8>)> = files
        .iter()
        .map(|f| {
            (
                f.strip_prefix(dir).unwrap().to_path_buf(),
                std::fs::read(f).unwrap_or_default(),
            )
        })
        .chain(links.iter().map(|(l, t)| {
            (
                l.strip_prefix(dir).unwrap().to_path_buf(),
                t.as_os_str().as_encoded_bytes().to_vec(),
            )
        }))
        .collect();
    out.sort();
    out
}

/// What a summary says, to compare.
fn told(summary: &Summary) -> String {
    let damaged: Vec<_> = summary
        .damaged
        .iter()
        .map(|d| (d.error.to_string(), d.kept))
        .collect();
    let skipped: Vec<_> = summary.skipped.iter().map(|e| e.to_string()).collect();
    format!(
        "{} {} {} {} {skipped:?} {damaged:?}",
        summary.files, summary.directories, summary.links, summary.bytes
    )
}

/// Whether `target`, read from the directory of `link`, stays under
/// `root`, by its text.
fn inside(root: &Path, link: &Path, target: &Path) -> bool {
    let Ok(start) = link.parent().unwrap_or(root).strip_prefix(root) else {
        return false;
    };
    let mut depth = start.components().count();
    for component in target.components() {
        match component {
            std::path::Component::ParentDir => {
                if depth == 0 {
                    return false;
                }
                depth -= 1;
            }
            std::path::Component::Normal(_) => depth += 1,
            std::path::Component::CurDir => {}
            _ => return false,
        }
    }
    true
}

fuzz_target!(|data: &[u8]| {
    let Some((&choice, image)) = data.split_first() else {
        return;
    };
    let Ok(mut fs) = Squashfs::open(Cursor::new(image)) else {
        return;
    };
    let mut options = Options::default();
    options.links =
        [Links::Refuse, Links::AsFile, Links::Inside, Links::Any][usize::from(choice & 3)];
    options.names = if choice & 4 != 0 {
        Names::Sanitize
    } else {
        Names::Strict
    };
    options.backslash_separator = choice & 8 != 0;
    options.on_refused = if choice & 32 != 0 {
        OnRefused::Skip
    } else {
        OnRefused::Stop
    };
    options.overwrite = choice & 64 != 0;
    // Small limits keep each run short.
    options.limits.max_entry_size = 256 << 10;
    options.limits.max_total_size = 1 << 20;
    options.limits.max_entries = 200;
    let threaded = (image.len() / 16) % 2 == 1;
    options.threads = if threaded {
        Threads::of(3)
    } else {
        Threads::One
    };
    // The bytes written when the last entry was, the reports so far, and the
    // most bytes told; cancelled after some, which the input's length picks.
    let seen = Arc::new(Mutex::new((0u64, 0u64, 0usize, 0u64)));
    let cancel_after = (choice & 128 != 0).then_some(image.len() % 16);
    let cancel = Cancel::new();
    options.cancel = Some(cancel.clone());
    let record = Arc::clone(&seen);
    options.progress = Some(Arc::new(move |progress: &Progress| {
        let mut seen = record.lock().unwrap();
        let (entries, done, reports, told) = &mut *seen;
        if progress.entries > *entries {
            (*entries, *done) = (progress.entries, progress.bytes);
        }
        assert!(
            progress.bytes >= *told,
            "told less than before: {progress:?}"
        );
        *told = progress.bytes;
        assert!(progress.bytes <= progress.total_bytes, "{progress:?}");
        if Some(*reports) == cancel_after {
            cancel.cancel();
        }
        *reports += 1;
    }));

    let scratch = std::env::temp_dir().join(format!(
        "hivepack-fuzz-extract-squashfs-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&scratch);
    if std::fs::create_dir_all(&scratch).is_err() {
        return;
    }
    let sentinel = scratch.join("sentinel");
    if std::fs::write(&sentinel, b"untouched").is_err() {
        return;
    }
    let out = scratch.join("out");
    let result = extract_squashfs(&mut fs, &out, &options);

    let mut around: Vec<_> = std::fs::read_dir(&scratch)
        .map(|entries| entries.flatten().map(|e| e.file_name()).collect())
        .unwrap_or_default();
    around.sort();
    let expected: &[&str] = if out.exists() {
        &["out", "sentinel"]
    } else {
        &["sentinel"]
    };
    assert_eq!(around, expected, "written beside the destination");
    assert_eq!(
        std::fs::read(&sentinel).ok().as_deref(),
        Some(&b"untouched"[..])
    );

    let (mut files, mut links) = (Vec::new(), Vec::new());
    walk(&out, &mut files, &mut links);
    for (link, target) in &links {
        // Created only as asked; with Any, anywhere, but nothing written
        // through it (nothing beside the destination, above).
        assert!(
            matches!(options.links, Links::Inside | Links::Any),
            "a link created: {link:?}"
        );
        if options.links == Links::Inside {
            assert!(
                inside(&out, link, target),
                "{link:?} leads outside: {target:?}"
            );
        }
    }
    // A hard link's file once.
    let mut inodes = HashSet::new();
    let on_disk: u64 = files
        .iter()
        .filter_map(|file| std::fs::symlink_metadata(file).ok())
        .filter(|m| inodes.insert((m.dev(), m.ino())))
        .map(|m| m.len())
        .sum();
    let (_, done, _, most) = *seen.lock().unwrap();
    if threaded {
        assert!(on_disk <= most, "more left than told written: {result:?}");
    } else {
        assert_eq!(on_disk, done, "a file cut off is left: {result:?}");
    }
    if let Ok(summary) = &result {
        assert_eq!(files.len() as u64, summary.files);
        assert_eq!(links.len() as u64, summary.links);
        assert_eq!(on_disk, summary.bytes);
    }

    // Threads write what one thread does, when nothing cancels them.
    if threaded && cancel_after.is_none() {
        let Ok(mut fs) = Squashfs::open(Cursor::new(image)) else {
            panic!("opened once, not twice");
        };
        let one = scratch.join("one");
        options.threads = Threads::One;
        options.progress = None;
        let alone = extract_squashfs(&mut fs, &one, &options);
        match (&result, &alone) {
            (Ok(threads), Ok(alone)) => {
                assert_eq!(told(threads), told(alone));
                assert_eq!(tree(&out), tree(&one));
            }
            (Err(_), Err(_)) => {}
            _ => panic!("threads: {result:?}, one: {alone:?}"),
        }
    }
});
