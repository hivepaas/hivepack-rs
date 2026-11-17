//! hivepack::ext on any input: the file system an ext2, ext3 or ext4 image
//! holds, walked whole, every file read, every symbolic link followed,
//! every inode's extended attributes read, and every path looked up again.
//!
//! The walk and the reads are made twice, in pieces of different sizes the
//! first eight bytes' hash picks, and the two must agree: what a file holds
//! does not depend on how it was asked for. A panic is a bug, and so is a
//! disagreement.
//!
//! The caps are what keep a crafted image from being answered for ever: up
//! to 4096 entries and 4 MiB of data altogether, which the reader's own
//! limits (a depth of 1024, a directory walked once, an attribute of 1 MiB)
//! sit inside.

#![no_main]

use std::io::Read;

use hivepack::ext::{Ext, What};
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

/// What one thing the walk came to holds: a file's bytes, a link's target,
/// or the error either ended in, and the attributes beside it.
type Held = (Vec<u8>, u32, Vec<u8>, Option<String>, String);

/// Every name the walk comes to, with what each one holds.
fn tree<D: Disk>(fs: &Ext<D>, mut seed: u64) -> Vec<Held> {
    let mut found: Vec<Held> = Vec::new();
    let mut read = 0usize;
    let mut walk = match fs.walk() {
        Ok(walk) => walk,
        Err(e) => {
            return vec![(
                Vec::new(),
                0,
                Vec::new(),
                Some(e.to_string()),
                String::new(),
            )];
        }
    };
    loop {
        if found.len() >= MAX_ENTRIES {
            return found;
        }
        let step = match walk.next(fs) {
            Ok(Some(step)) => step,
            Ok(None) => return found,
            Err(e) => {
                found.push((
                    Vec::new(),
                    0,
                    Vec::new(),
                    Some(e.to_string()),
                    String::new(),
                ));
                return found;
            }
        };
        // Looked up again, for the lookup's own sake. Not asserted to be
        // found: a name is bytes, and a crafted one may hold the separator
        // a path is cut on, so the path the walk built may not read back.
        let _ = fs.lookup_path(&step.path);

        // The attributes beside it, which is where a file system keeps
        // SELinux labels, capabilities and ACLs.
        let xattrs = match fs.xattrs(&step.node) {
            Ok(found) => format!("{found:?}"),
            Err(e) => e.to_string(),
        };

        let mut body = Vec::new();
        let mut ended = None;
        match step.node.what {
            What::File => match fs.file(&step.node) {
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
            },
            What::Symlink => match fs.read_link(&step.node) {
                Ok(target) => body = target,
                Err(e) => ended = Some(e.to_string()),
            },
            _ => {}
        }
        found.push((step.path, step.node.ino, body, ended, xattrs));
    }
}

fuzz_target!(|data: &[u8]| {
    let Ok(fs) = Ext::open(data) else {
        return;
    };
    let seed = data
        .iter()
        .take(8)
        .fold(0u64, |h, &b| h.rotate_left(8) ^ u64::from(b));
    let _ = (
        fs.kind(),
        fs.label(),
        fs.uuid_text(),
        fs.block_size(),
        fs.blocks(),
        fs.inodes(),
    );
    assert_eq!(tree(&fs, seed), tree(&fs, !seed));
});
