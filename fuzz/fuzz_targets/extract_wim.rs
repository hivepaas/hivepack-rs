//! Extracts the input as one image of a WIM archive with
//! hivepack::extract, as the `extract_squashfs` target does a SquashFS
//! image: its first byte choosing the options and the image to take, the
//! rest the archive, into a scratch folder beside a file that must stay as
//! it was.
//!
//! A panic is a bug, and so is a file written outside the destination, a
//! count the summary does not give, or a file left cut off: the files left
//! hold the bytes of the entries written in full, however the extraction
//! ends. A file under two names is written once and counted once, which is
//! what a WIM's sets of names are for.
//!
//! `crates/hivepack/tests/extract_wim.rs` has the cases wimlib writes.

#![no_main]

use std::collections::HashSet;
use std::io::Cursor;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use hivepack::extract::{Links, Names, OnRefused, Options, Progress, extract_wim};
use hivepack::wim::Wim;
use libfuzzer_sys::fuzz_target;

/// The files and links under `dir`.
fn walk(dir: &Path, files: &mut Vec<PathBuf>, links: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let Ok(metadata) = std::fs::symlink_metadata(&path) else {
            continue;
        };
        if metadata.is_symlink() {
            links.push(path);
        } else if metadata.is_dir() {
            walk(&path, files, links);
        } else {
            files.push(path);
        }
    }
}

fuzz_target!(|data: &[u8]| {
    let Some((&choice, archive)) = data.split_first() else {
        return;
    };
    let Ok(mut wim) = Wim::open(Cursor::new(archive)) else {
        return;
    };
    // The image the byte picks, and one that is not there where there are
    // none: an archive naming no image is refused, not extracted.
    let images: Vec<u32> = wim.images().iter().map(|image| image.index).collect();
    let image = match images.len() {
        0 => 1,
        count => images[usize::from(choice >> 5) % count],
    };

    let mut options = Options::default();
    options.links =
        [Links::Refuse, Links::AsFile, Links::Inside, Links::Any][usize::from(choice & 3)];
    options.names = if choice & 4 != 0 {
        Names::Sanitize
    } else {
        Names::Strict
    };
    options.on_refused = if choice & 8 != 0 {
        OnRefused::Skip
    } else {
        OnRefused::Stop
    };
    options.overwrite = choice & 16 != 0;
    // Small limits keep each run short.
    options.limits.max_entry_size = 256 << 10;
    options.limits.max_total_size = 1 << 20;
    options.limits.max_entries = 200;
    // The bytes written as the last entry was, to hold what is left
    // against what was told.
    let seen = Arc::new(Mutex::new((0u64, 0u64, 0u64)));
    let record = Arc::clone(&seen);
    options.progress = Some(Arc::new(move |progress: &Progress| {
        let mut seen = record.lock().unwrap();
        let (entries, done, told) = &mut *seen;
        if progress.entries > *entries {
            (*entries, *done) = (progress.entries, progress.bytes);
        }
        assert!(
            progress.bytes >= *told,
            "told less than before: {progress:?}"
        );
        *told = progress.bytes;
        assert!(progress.bytes <= progress.total_bytes, "{progress:?}");
    }));

    let scratch =
        std::env::temp_dir().join(format!("hivepack-fuzz-extract-wim-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&scratch);
    if std::fs::create_dir_all(&scratch).is_err() {
        return;
    }
    let sentinel = scratch.join("sentinel");
    if std::fs::write(&sentinel, b"untouched").is_err() {
        return;
    }
    let out = scratch.join("out");
    let result = extract_wim(&mut wim, image, &out, &options);

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
    // A WIM's reparse points are refused, so nothing here creates a link;
    // `Links::AsFile` copies the file a set of names shares.
    assert!(links.is_empty(), "a link created: {links:?}");
    // A file under two names is one file on the disk, and its bytes count
    // once.
    let mut inodes = HashSet::new();
    let on_disk: u64 = files
        .iter()
        .filter_map(|file| std::fs::symlink_metadata(file).ok())
        .filter(|m| inodes.insert((m.dev(), m.ino())))
        .map(|m| m.len())
        .sum();
    let (_, done, _) = *seen.lock().unwrap();
    assert_eq!(on_disk, done, "a file cut off is left: {result:?}");
    if let Ok(summary) = &result {
        assert_eq!(files.len() as u64, summary.files);
        assert_eq!(on_disk, summary.bytes);
    }
    let _ = std::fs::remove_dir_all(&scratch);
});
