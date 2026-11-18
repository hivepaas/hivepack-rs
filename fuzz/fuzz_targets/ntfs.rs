//! hivepack::ntfs on any input: the file system an NTFS image holds,
//! walked whole, every file read, every stream beside a file read, and
//! every path looked up again.
//!
//! The walk and the reads are made twice, in pieces of different sizes the
//! first eight bytes' hash picks, and the two must agree: what a file
//! holds does not depend on how it was asked for. A panic is a bug, and so
//! is a disagreement.
//!
//! **This target is not in CI yet, and it is the only one that is not.**
//! NTFS is read by a dependency, and the released version of it panics on
//! a damaged directory index — `index_entry.rs:205`, a u16 read at offset
//! 8 of a slice the entry's own length has truncated below its header.
//! This target reaches it: with a damaged image in the corpus it dies on
//! that line at once, measured. hivepack cannot fix it from outside the
//! library; upstream's PR #41 does, and nothing is released with it. So
//! this is run by hand until a release carries the fix, and the step that
//! runs it goes in with the bump that takes it. docs/ntfs.md has the
//! numbers.
//!
//! **Two things it needs, or it proves nothing.** A real NTFS image in
//! the corpus, because the name is checked when the file system is opened
//! and random bytes never get past it. And `-max_len` at least as long as
//! that image: without it libFuzzer says "will not generate inputs larger
//! than 1048576 bytes" and cuts the seeds down to that, which leaves a
//! disk whose `$MFT` is off the end, so nothing behind the boot sector is
//! ever read. Two runs of 121 and 61 seconds, 3.8 and 2.0 million
//! executions, found nothing that way with a crashing image sitting in
//! the corpus; the same corpus with `-max_len=8388608` died immediately.
//!
//! The caps are what keep a crafted image from being answered for ever:
//! up to 4096 entries and 4 MiB of data altogether, which the reader's own
//! limits (a depth of 1024, a directory walked once, the runs of one file)
//! sit inside.

#![no_main]

use std::io::Read;

use hivepack::image::Disk;
use hivepack::ntfs::Ntfs;
use libfuzzer_sys::fuzz_target;

const MAX_ENTRIES: usize = 4096;
const MAX_DATA: usize = 4 << 20;

/// The next size to read in, between 1 byte and 64 KiB.
fn next(seed: &mut u64) -> usize {
    *seed = seed
        .wrapping_mul(6364136223846793005)
        .wrapping_add(1442695040888963407);
    1 + (*seed >> 48) as usize
}

/// What one stream of a file holds, and how reading it ended.
type Stream = (Vec<u8>, Option<String>);

/// Every name the walk comes to, with what each file holds, what the
/// streams beside it hold, and how each read ended.
#[allow(clippy::type_complexity)]
fn tree<D: Disk>(
    fs: &Ntfs<D>,
    mut seed: u64,
) -> Vec<(String, u64, Stream, Vec<(String, Stream)>)> {
    let mut found = Vec::new();
    let mut read = 0usize;
    let mut walk = match fs.walk() {
        Ok(walk) => walk,
        Err(e) => {
            return vec![(
                String::new(),
                0,
                (Vec::new(), Some(e.to_string())),
                Vec::new(),
            )];
        }
    };
    loop {
        if found.len() >= MAX_ENTRIES {
            return found;
        }
        let (path, entry) = match walk.next(fs) {
            Ok(Some(step)) => step,
            Ok(None) => return found,
            Err(e) => {
                found.push((
                    String::new(),
                    0,
                    (Vec::new(), Some(e.to_string())),
                    Vec::new(),
                ));
                return found;
            }
        };
        // Looked up again, for the lookup's own sake. Not asserted to be
        // found: a name may hold the separator a path is cut on, and then
        // the path the walk built cannot be read back.
        let _ = fs.lookup_path(&path);

        let mut body = (Vec::new(), None);
        let mut streams = Vec::new();
        if entry.is_file() {
            body = whole(fs, &entry, None, &mut seed, &mut read);
            // The streams a file may have beside its own data, which are
            // named $DATA attributes of the same record.
            if let Ok(names) = fs.streams(&entry) {
                for name in names {
                    let held = whole(fs, &entry, Some(&name), &mut seed, &mut read);
                    streams.push((name, held));
                }
            }
        }
        found.push((path, entry.size, body, streams));
    }
}

/// One stream read whole, in pieces of the sizes the seed picks.
fn whole<D: Disk>(
    fs: &Ntfs<D>,
    entry: &hivepack::ntfs::Entry,
    name: Option<&str>,
    seed: &mut u64,
    read: &mut usize,
) -> Stream {
    let opened = match name {
        Some(name) => fs.stream(entry, name),
        None => fs.file(entry),
    };
    let mut file = match opened {
        Ok(file) => file,
        Err(e) => return (Vec::new(), Some(e.to_string())),
    };
    let mut body = Vec::new();
    while *read < MAX_DATA {
        let mut buf = vec![0u8; next(seed).min(MAX_DATA - *read)];
        match file.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                body.extend_from_slice(&buf[..n]);
                *read += n;
            }
            Err(e) => return (body, Some(e.to_string())),
        }
    }
    (body, None)
}

fuzz_target!(|data: &[u8]| {
    let Ok(fs) = Ntfs::open(data) else {
        return;
    };
    let seed = data
        .iter()
        .take(8)
        .fold(0u64, |h, &b| h.rotate_left(8) ^ u64::from(b));
    let _ = (fs.label(), fs.cluster_size(), fs.size());
    assert_eq!(tree(&fs, seed), tree(&fs, !seed));
});
