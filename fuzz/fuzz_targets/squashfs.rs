//! hivepack::squashfs on any image: the input is the image. It is opened
//! and walked twice, as `tests/squashfs_oracle.rs` walks it beside
//! squashfuse: every entry, its inode, attributes, link target, extended
//! attributes, export table entry and up to 256 KiB of its data, and each
//! directory without an index listed again from each of its entries'
//! `next_offset`. Both walks must give the same transcript, a directory
//! listed from an entry's `next_offset` must give the entry after it, and a panic is a bug. What
//! a walk holds is bounded: 4,096 entries, the caches' blocks, and what the
//! image has room for.

#![no_main]

use std::io::Cursor;

use hivepack::squashfs::{Squashfs, Step};
use libfuzzer_sys::fuzz_target;

const MAX_ENTRIES: usize = 4096;
const MAX_DATA: u64 = 256 << 10;

/// The image, walked: one line per thing seen.
fn walk(data: &[u8]) -> Vec<String> {
    let mut fs = match Squashfs::open(Cursor::new(data)) {
        Ok(fs) => fs,
        Err(e) => return vec![e.to_string()],
    };
    let mut out = vec![format!("{:?}", fs.superblock())];
    let root = match fs.root() {
        Ok(root) => root,
        Err(e) => {
            out.push(e.to_string());
            return out;
        }
    };
    let mut trv = match fs.traverse(&root) {
        Ok(trv) => trv,
        Err(e) => {
            out.push(e.to_string());
            return out;
        }
    };
    let mut entries = 0;
    let mut buf = vec![0u8; 65536];
    while entries < MAX_ENTRIES {
        let (path, entry) = match trv.next(&mut fs) {
            Ok(Some(Step::Entry { path, entry })) => (path, entry),
            Ok(Some(Step::DirEnd)) => {
                out.push("up".into());
                continue;
            }
            Ok(None) => break,
            Err(e) => {
                out.push(e.to_string());
                break;
            }
        };
        entries += 1;
        out.push(format!("{path:?} {entry:?}"));
        let inode = match fs.inode(entry.inode) {
            Ok(inode) => inode,
            Err(e) => {
                out.push(e.to_string());
                continue;
            }
        };
        out.push(format!("{inode:?} {:?}", fs.stat(&inode)));
        if inode.is_symlink() {
            out.push(format!("{:?}", fs.read_link(&inode).map(|t| t.len())));
        }
        if let Ok(xattrs) = fs.xattrs(&inode) {
            for x in xattrs {
                out.push(format!("{x:?}"));
            }
        }
        if fs.export_ok() {
            out.push(format!("{:?}", fs.export_inode(entry.inode_number)));
        }
        if inode.is_file() {
            let mut at = 0;
            while at < inode.file_size().min(MAX_DATA) {
                match fs.read_at(&inode, at, &mut buf) {
                    Ok(n) => at += n as u64,
                    Err(e) => {
                        out.push(e.to_string());
                        break;
                    }
                }
            }
            out.push(format!("data {at}"));
        }
        // Without an index (which a damaged image can make lead elsewhere),
        // listed whole, then from each entry's next_offset.
        if inode.is_dir() && inode.dir_info().3 == 0 {
            let listed: Vec<_> = match fs.read_dir(&inode) {
                Ok(list) => list.take(64).collect(),
                Err(_) => Vec::new(),
            };
            for (i, item) in listed.iter().enumerate() {
                let Ok(item) = item else { break };
                if let Ok(mut again) = fs.read_dir_at(&inode, item.next_offset) {
                    if let (Some(Ok(next)), Some(Ok(expected))) = (again.next(), listed.get(i + 1))
                    {
                        assert_eq!(&next, expected, "listed again from {}", item.next_offset);
                    }
                }
            }
        }
    }
    out
}

fuzz_target!(|data: &[u8]| {
    let first = walk(data);
    let second = walk(data);
    assert_eq!(first, second);
});
