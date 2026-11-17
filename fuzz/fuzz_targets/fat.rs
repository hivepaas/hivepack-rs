//! hivepack::fat on any input: the file system a FAT12, FAT16 or FAT32
//! image holds, walked whole, every file read, and every path looked up
//! again.
//!
//! The walk and the reads are made twice, in pieces of different sizes the
//! first eight bytes' hash picks, and the two must agree: what a file holds
//! does not depend on how it was asked for. A panic is a bug, and so is a
//! disagreement.
//!
//! The caps are what keep a crafted image from being answered for ever: up
//! to 4096 entries and 4 MiB of data altogether, which the reader's own
//! limits (a chain no longer than the clusters it has, 16 MiB of records, a
//! depth of 1024) sit inside.

#![no_main]

use std::io::Read;

use hivepack::fat::Fat;
use hivepack::image::Disk;
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

/// Every name the walk comes to, with what each file holds and how reading
/// it ended.
fn tree<D: Disk>(fs: &Fat<D>, mut seed: u64) -> Vec<(String, u64, Vec<u8>, Option<String>)> {
    let mut found = Vec::new();
    let mut read = 0usize;
    let mut walk = match fs.walk() {
        Ok(walk) => walk,
        Err(e) => return vec![(String::new(), 0, Vec::new(), Some(e.to_string()))],
    };
    loop {
        if found.len() >= MAX_ENTRIES {
            return found;
        }
        let (path, entry) = match walk.next(fs) {
            Ok(Some(step)) => step,
            Ok(None) => return found,
            Err(e) => {
                found.push((String::new(), 0, Vec::new(), Some(e.to_string())));
                return found;
            }
        };
        // Looked up again, for the lookup's own sake. Not asserted to be
        // found: a crafted long name may hold the separator a path is cut
        // on, and then the path the walk built cannot be read back.
        let _ = fs.lookup_path(&path);

        let mut body = Vec::new();
        let mut ended = None;
        if !entry.is_dir() {
            match fs.file(&entry) {
                Ok(mut file) => {
                    while read < MAX_DATA {
                        let mut buf = vec![0u8; next(&mut seed).min(MAX_DATA - read)];
                        match file.read(&mut buf) {
                            Ok(0) => break,
                            Ok(n) => {
                                body.extend_from_slice(&buf[..n]);
                                read += n;
                            }
                            Err(e) => {
                                ended = Some(e.to_string());
                                break;
                            }
                        }
                    }
                }
                Err(e) => ended = Some(e.to_string()),
            }
        }
        found.push((path, entry.size, body, ended));
    }
}

fuzz_target!(|data: &[u8]| {
    let Ok(fs) = Fat::open(data) else {
        return;
    };
    let seed = data
        .iter()
        .take(8)
        .fold(0u64, |h, &b| h.rotate_left(8) ^ u64::from(b));
    let _ = (fs.kind(), fs.label(), fs.cluster_size(), fs.clusters());
    assert_eq!(tree(&fs, seed), tree(&fs, !seed));
});
