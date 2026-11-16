//! ext2, ext3 and ext4 file systems: a tree put into one by `mke2fs -d` and
//! read back out of it, against the bytes that went in and against what
//! `debugfs` reads of the same image; and file systems built byte by byte,
//! each of which `e2fsck` is run over, so that a test passing is not the
//! reader agreeing with its own mistake.
//!
//! See crates/hivepack/src/ext/ and docs/ext.md.

#![cfg(all(feature = "ext", feature = "image"))]
#![allow(clippy::unwrap_used)]

use std::collections::BTreeMap;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Command;

use hivepack::ext::{Error, Ext, Kind, Unsupported, What};
use hivepack::image::{Disk, Part, Table, partitions};

/// A folder in the system's temporary one, removed when dropped.
struct Scratch(PathBuf);

impl Scratch {
    fn new(what: &str) -> Scratch {
        let path = std::env::temp_dir().join(format!(
            "hivepack-ext-{}-{}",
            std::process::id(),
            what.replace([' ', '/', '^', ','], "-")
        ));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).unwrap();
        Scratch(path)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A tool, if it is installed and can be run: see image_vhd.rs, which says
/// why the second half matters — CI's 32-bit container answers `ENOSYS` to
/// starting a process at all.
fn tool(name: &str) -> Option<PathBuf> {
    let path = ["/usr/sbin", "/usr/bin", "/sbin", "/bin", "/usr/local/sbin"]
        .into_iter()
        .map(|at| PathBuf::from(at).join(name))
        .find(|p| p.exists())?;
    Command::new(&path).arg("-V").output().ok()?;
    Some(path)
}

fn run(at: &Path, args: &[&str]) {
    let out = Command::new(at).args(args).output().unwrap();
    assert!(
        out.status.success(),
        "{at:?} {args:?} failed: {}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

/// What a tool said, whether or not it liked what it saw.
fn said(at: &Path, args: &[&str]) -> (bool, String) {
    let out = Command::new(at).args(args).output().unwrap();
    (
        out.status.success(),
        format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        ),
    )
}

/// `e2fsck` over an image, where it is installed: what says a file system
/// built here is one, rather than only one this reader likes.
fn sound(what: &str, image: &[u8]) {
    let Some(e2fsck) = tool("e2fsck") else {
        eprintln!("e2fsck cannot be run here: {what} is not checked by it");
        return;
    };
    let s = Scratch::new(&format!("fsck {what}"));
    let path = s.0.join("fs.img");
    std::fs::write(&path, image).unwrap();
    // -f to check even a file system marked clean, -n to answer no to
    // every offer to change it.
    let (ok, told) = said(&e2fsck, &["-fn", path.to_str().unwrap()]);
    assert!(ok, "{what}: e2fsck does not call this sound:\n{told}");
}

/// Bytes that are the same every run and not all alike.
fn pattern(len: usize, seed: u64) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(len);
    let mut x = seed | 1;
    for _ in 0..len {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        bytes.push((x >> 24) as u8);
    }
    bytes
}

/// One thing in a tree, as both the folder and the file system hold it.
#[derive(Debug, PartialEq, Eq)]
enum Thing {
    File(Vec<u8>),
    Dir,
    Link(Vec<u8>),
    /// Nothing a tree here puts in: a device, a pipe or a socket. Kept so
    /// that a file system answering one shows up as what it is rather than
    /// as a test that stops.
    Other(What),
}

/// A folder of files to put into a file system, and what should come back
/// out of it.
///
/// Only where the system this is built for has symbolic links and names
/// that are bytes, which is where `mke2fs` is as well. What is read out of
/// an image rather than put into one is checked everywhere: the half built
/// byte by byte holds links and a name that is not UTF-8 too.
#[cfg(unix)]
fn a_tree(at: &Path) -> BTreeMap<Vec<u8>, Thing> {
    let mut want: BTreeMap<Vec<u8>, Thing> = BTreeMap::new();
    let mut file = |path: &str, bytes: Vec<u8>| {
        let whole = at.join(path);
        std::fs::create_dir_all(whole.parent().unwrap()).unwrap();
        std::fs::write(&whole, &bytes).unwrap();
        want.insert(path.as_bytes().to_vec(), Thing::File(bytes));
    };
    file("short.txt", b"a few bytes\n".to_vec());
    file("empty.dat", Vec::new());
    // Longer than the twelve blocks an inode holds numbers for, and longer
    // than one block of numbers after them: with blocks of 1 KiB this is
    // read through two levels of indirect blocks.
    file("double.bin", pattern(400_000, 7));
    file("sub/deep/inside.txt", b"two folders down\n".to_vec());
    want.insert(b"sub".to_vec(), Thing::Dir);
    want.insert(b"sub/deep".to_vec(), Thing::Dir);

    // A file with holes: what is in a hole is zeroes, and nothing is
    // written for it.
    let mut holey = vec![0u8; 900_000];
    holey[1000..1014].copy_from_slice(b"near the front");
    holey[880_000..880_021].copy_from_slice(b"and near the end     ");
    let whole = at.join("holes.bin");
    std::fs::write(&whole, &holey).unwrap();
    want.insert(b"holes.bin".to_vec(), Thing::File(holey));

    // Both kinds of symbolic link: one short enough to be kept in the
    // inode itself, and one that needs a block of its own.
    let long = "/a/very/long/target/that/will/not/fit/in/the/sixty/bytes/of/the/inode/itself";
    for (name, to) in [("link", "short.txt"), ("longlink", long)] {
        std::os::unix::fs::symlink(to, at.join(name)).unwrap();
        want.insert(
            name.as_bytes().to_vec(),
            Thing::Link(to.as_bytes().to_vec()),
        );
    }

    // A name that is not UTF-8. Linux puts no meaning on a name's bytes
    // beyond `/` and the byte that ends a string, so a reader that made
    // text of one would answer a name that is not the file's.
    use std::os::unix::ffi::OsStrExt;
    let odd = std::ffi::OsStr::from_bytes(b"not\xffutf8.txt");
    std::fs::write(at.join(odd), b"bytes are bytes\n").unwrap();
    want.insert(
        b"not\xffutf8.txt".to_vec(),
        Thing::File(b"bytes are bytes\n".to_vec()),
    );

    // Two names for one file, which is one inode with two of them.
    std::fs::hard_link(at.join("short.txt"), at.join("also.txt")).unwrap();
    want.insert(b"also.txt".to_vec(), Thing::File(b"a few bytes\n".to_vec()));

    // What `mke2fs` puts in every file system it makes.
    want.insert(b"lost+found".to_vec(), Thing::Dir);
    want
}

/// Everything the file system holds, by its path.
fn what_it_holds<D: Disk>(fs: &Ext<D>) -> BTreeMap<Vec<u8>, Thing> {
    let mut holds = BTreeMap::new();
    let mut walk = fs.walk().unwrap();
    while let Some(step) = walk.next(fs).unwrap() {
        let what = match step.node.what {
            What::Dir => Thing::Dir,
            What::Symlink => Thing::Link(fs.read_link(&step.node).unwrap()),
            What::File => {
                let mut data = Vec::new();
                // Read in pieces that do not line up with the blocks.
                let mut file = fs.file(&step.node).unwrap();
                let mut piece = vec![0u8; 3571];
                loop {
                    let read = file.read(&mut piece).unwrap();
                    if read == 0 {
                        break;
                    }
                    data.extend_from_slice(&piece[..read]);
                }
                assert_eq!(
                    data.len() as u64,
                    step.node.size,
                    "{}: as many bytes as the inode says",
                    step.entry.name_text()
                );
                Thing::File(data)
            }
            other => Thing::Other(other),
        };
        // What the record says a thing is, is what the inode says it is.
        if let Some(told) = step.entry.what {
            assert_eq!(told, step.node.what, "{}", step.entry.name_text());
        }
        assert!(holds.insert(step.path.clone(), what).is_none(), "twice");
    }
    holds
}

/// A tree through `mke2fs -d`, which puts a folder into a new file system,
/// and then read back.
#[cfg(unix)]
fn through_mkfs(kind: &str, options: &[&str]) {
    let what = format!("{kind} {}", options.join(" "));
    let Some(mkfs) = tool(&format!("mkfs.{kind}")) else {
        eprintln!("mkfs.{kind} cannot be run here: {what} is not checked against it");
        return;
    };
    let s = Scratch::new(&what);
    let from = s.0.join("tree");
    std::fs::create_dir_all(&from).unwrap();
    let want = a_tree(&from);
    let image = s.0.join("fs.img");
    // Room for the tree with plenty over, so that nothing fails for want
    // of blocks.
    std::fs::write(&image, vec![0u8; 48 << 20]).unwrap();
    let mut args = vec!["-q", "-F", "-d", from.to_str().unwrap()];
    args.extend_from_slice(options);
    args.push(image.to_str().unwrap());
    run(&mkfs, &args);

    let raw = std::fs::read(&image).unwrap();
    sound(&what, &raw);
    let fs = Ext::open(&raw).map_err(|e| format!("{what}: {e}")).unwrap();
    assert_eq!(
        what_it_holds(&fs),
        want,
        "{what}: not the tree that went in"
    );

    // The two names of one file are one inode, and it says so.
    let one = fs.lookup_path("short.txt").unwrap().unwrap();
    let other = fs.lookup_path("also.txt").unwrap().unwrap();
    assert_eq!(one.ino, other.ino, "{what}: one inode, two names");
    assert_eq!(one.links, 2, "{what}");

    // What `debugfs` reads of the same image, which is another reader of
    // the format and not this one.
    against_debugfs(&what, &image, &fs);
}

/// What `debugfs` says about the same file system: the inode of a few
/// paths, and the bytes of a file it dumps itself.
#[cfg(unix)]
fn against_debugfs<D: Disk>(what: &str, image: &Path, fs: &Ext<D>) {
    let Some(debugfs) = tool("debugfs") else {
        eprintln!("debugfs cannot be run here: {what} is not checked against it");
        return;
    };
    for path in ["short.txt", "double.bin", "holes.bin", "sub/deep", "link"] {
        let node = fs.lookup_path(path).unwrap().unwrap();
        let (ok, told) = said(
            &debugfs,
            &["-R", &format!("stat /{path}"), image.to_str().unwrap()],
        );
        assert!(ok, "{what}: debugfs could not stat /{path}:\n{told}");
        // Its output is `Name:` and a value, several to a line, lined up
        // with spaces rather than one space along.
        let number = |name: &str| -> Option<u64> {
            let at = told.find(&format!("{name}:"))? + name.len() + 1;
            let rest = told[at..].trim_start();
            let end = rest
                .find(|c: char| !c.is_ascii_digit())
                .unwrap_or(rest.len());
            rest[..end].parse().ok()
        };
        assert_eq!(
            number("Inode"),
            Some(u64::from(node.ino)),
            "{what}: /{path}"
        );
        assert_eq!(number("Size"), Some(node.size), "{what}: /{path} size");
        assert_eq!(number("User"), Some(u64::from(node.uid)), "{what}: /{path}");
        assert_eq!(
            number("Group"),
            Some(u64::from(node.gid)),
            "{what}: /{path}"
        );
        assert_eq!(
            number("Links"),
            Some(u64::from(node.links)),
            "{what}: /{path} links"
        );
        // The mode is in octal, and may be of three digits or four.
        let mode = told.find("Mode:").and_then(|at| {
            let rest = told[at + 5..].trim_start();
            let end = rest.find(|c: char| !c.is_digit(8)).unwrap_or(rest.len());
            u16::from_str_radix(&rest[..end], 8).ok()
        });
        assert_eq!(mode, Some(node.mode), "{what}: /{path} mode");
    }

    // A file `debugfs` dumps with its own reader, byte for byte against
    // what this one reads.
    let s = Scratch::new(&format!("dump {what}"));
    for path in ["double.bin", "holes.bin"] {
        let out = s.0.join("out");
        run(
            &debugfs,
            &[
                "-R",
                &format!("dump /{path} {}", out.to_str().unwrap()),
                image.to_str().unwrap(),
            ],
        );
        let theirs = std::fs::read(&out).unwrap();
        let node = fs.lookup_path(path).unwrap().unwrap();
        let mut mine = Vec::new();
        fs.file(&node).unwrap().read_to_end(&mut mine).unwrap();
        let differs = mine.iter().zip(&theirs).position(|(a, b)| a != b);
        assert!(
            differs.is_none() && mine.len() == theirs.len(),
            "{what}: /{path} differs from what debugfs dumps, at byte {differs:?}"
        );
    }
}

#[test]
#[cfg(unix)]
fn an_ext4_file_system_reads_as_the_tree_that_went_into_it() {
    through_mkfs("ext4", &["-b", "1024"]);
}

#[test]
#[cfg(unix)]
fn an_ext2_file_system_reads_as_the_tree_that_went_into_it() {
    // No journal, no extents: the block numbers in the inode and the
    // indirect blocks they lead to, which is what ext2 had.
    through_mkfs("ext2", &["-b", "1024"]);
}

#[test]
#[cfg(unix)]
fn an_ext3_file_system_reads_as_the_tree_that_went_into_it() {
    through_mkfs("ext3", &["-b", "1024"]);
}

/// The layouts one file system may have and another may not, each read for
/// the same tree: 128-byte inodes, which have no room for nanoseconds or
/// for when a file was made; group descriptors of 32 bytes and of 64; an
/// ext4 whose files are mapped as ext2's were; a directory record that says
/// nothing about what it names; and blocks of 1, 2 and 4 KiB.
#[test]
#[cfg(unix)]
fn the_layouts_a_file_system_may_have_are_each_read() {
    for (kind, options) in [
        ("ext2", vec!["-b", "1024", "-I", "128"]),
        ("ext2", vec!["-b", "1024", "-O", "^filetype"]),
        ("ext2", vec!["-b", "2048"]),
        ("ext4", vec!["-b", "1024", "-O", "^64bit"]),
        ("ext4", vec!["-b", "1024", "-O", "^metadata_csum"]),
        (
            "ext4",
            vec!["-b", "1024", "-O", "^extent,^64bit,^metadata_csum"],
        ),
        ("ext4", vec!["-b", "4096"]),
        ("ext4", vec!["-b", "4096", "-I", "1024"]),
    ] {
        through_mkfs(kind, &options);
    }
}

/// What each of the three is called, which nothing in the file system says:
/// it is read off the features it has, as `blkid` reads it.
#[test]
fn what_a_file_system_is_called_is_read_off_what_it_has() {
    for (kind, want) in [
        ("ext2", Kind::Ext2),
        ("ext3", Kind::Ext3),
        ("ext4", Kind::Ext4),
    ] {
        let Some(mkfs) = tool(&format!("mkfs.{kind}")) else {
            eprintln!("mkfs.{kind} cannot be run here: its name is not checked");
            return;
        };
        let s = Scratch::new(&format!("named {kind}"));
        let image = s.0.join("fs.img");
        std::fs::write(&image, vec![0u8; 8 << 20]).unwrap();
        run(
            &mkfs,
            &["-q", "-F", "-L", "HIVEPACK", image.to_str().unwrap()],
        );
        let raw = std::fs::read(&image).unwrap();
        let fs = Ext::open(&raw).unwrap();
        assert_eq!(fs.kind(), want, "mkfs.{kind}");
        assert_eq!(fs.kind().says(), kind);
        assert_eq!(fs.label(), Some("HIVEPACK"));
        assert_eq!(fs.uuid_text().len(), 36);
        // Nothing in it but what `mke2fs` puts there.
        let root = fs.read_dir(&fs.root().unwrap()).unwrap();
        assert_eq!(root.len(), 1);
        assert_eq!(root[0].name, b"lost+found");
    }
}

/// The file systems `mke2fs` can make that are refused, each of which would
/// otherwise be read as a tree that is not on the disk.
#[test]
fn what_is_refused_is_refused_as_mke2fs_writes_it() {
    let Some(mkfs) = tool("mkfs.ext4") else {
        eprintln!("mkfs.ext4 cannot be run here: what is refused is not checked against it");
        return;
    };
    for (options, want) in [
        (vec!["-O", "bigalloc"], Unsupported::BigAlloc),
        (
            vec!["-O", "meta_bg", "-O", "^resize_inode"],
            Unsupported::MetaGroups,
        ),
        (vec!["-O", "encrypt"], Unsupported::Encrypted),
    ] {
        let s = Scratch::new(&format!("refused {}", options.join(" ")));
        let image = s.0.join("fs.img");
        std::fs::write(&image, vec![0u8; 32 << 20]).unwrap();
        let mut args = vec!["-q", "-F"];
        args.extend_from_slice(&options);
        args.push(image.to_str().unwrap());
        let (made, told) = said(&mkfs, &args);
        if !made {
            eprintln!(
                "mkfs.ext4 writes no {options:?} here, so {want:?} is checked by hand: {told}"
            );
            continue;
        }
        let raw = std::fs::read(&image).unwrap();
        let got = Ext::open(&raw);
        assert!(
            matches!(&got, Err(Error::Needs(needs)) if *needs == want),
            "{options:?}: wanted {want:?}, got {:?}",
            got.map(|_| "a file system").map_err(|e| e.to_string())
        );
    }
}

/// A file system that keeps what is small enough in the inode itself,
/// which `mke2fs -O inline_data` writes: the 60 bytes where the block
/// numbers would be, and the rest in the room the extended attributes are
/// in. A small directory goes there too, where its records are one run
/// rather than blocks of them and the four bytes in front of them are the
/// inode it is in.
///
/// This has a tree of its own rather than joining the layouts above,
/// because `mke2fs -O inline_data -d` does not write the tree it is given:
/// a file with a hole at its end comes out shorter than the file that went
/// in — 880640 bytes for one of 900000 — and `debugfs` says the same of
/// the image, so it is the tool and not this reader. The same `mke2fs`
/// without the feature writes the length the file has.
#[test]
#[cfg(unix)]
fn what_is_small_enough_to_be_in_the_inode_is_read_from_it() {
    let Some(mkfs) = tool("mkfs.ext4") else {
        eprintln!("mkfs.ext4 cannot be run here: data in the inode is not checked against it");
        return;
    };
    let s = Scratch::new("inline");
    let from = s.0.join("tree");
    std::fs::create_dir_all(from.join("sub")).unwrap();
    // One that fits in the inode, one that needs the attribute as well,
    // one far too long for either, and a folder.
    let mid = "a file of about ninety bytes, which is more than the sixty an inode holds itself\n";
    std::fs::write(from.join("tiny.txt"), b"tiny\n").unwrap();
    std::fs::write(from.join("mid.txt"), mid).unwrap();
    std::fs::write(from.join("big.bin"), pattern(5000, 11)).unwrap();
    std::fs::write(from.join("sub/inside.txt"), b"in a folder\n").unwrap();
    let image = s.0.join("fs.img");
    std::fs::write(&image, vec![0u8; 16 << 20]).unwrap();
    run(
        &mkfs,
        &[
            "-q",
            "-F",
            "-b",
            "1024",
            "-I",
            "256",
            "-O",
            "inline_data",
            "-d",
            from.to_str().unwrap(),
            image.to_str().unwrap(),
        ],
    );
    let raw = std::fs::read(&image).unwrap();
    sound("inline", &raw);
    let fs = Ext::open(&raw).unwrap();

    for (path, bytes) in [
        ("tiny.txt", b"tiny\n".to_vec()),
        ("mid.txt", mid.as_bytes().to_vec()),
        ("sub/inside.txt", b"in a folder\n".to_vec()),
    ] {
        let node = fs.lookup_path(path).unwrap().unwrap();
        assert!(node.is_inline(), "/{path} is small enough for its inode");
        assert_eq!(node.blocks, 0, "/{path} is given no blocks at all");
        let mut read = Vec::new();
        fs.file(&node).unwrap().read_to_end(&mut read).unwrap();
        assert_eq!(read, bytes, "/{path}");
        // The attribute the data is in is not an attribute of the file.
        assert!(
            fs.xattrs(&node).unwrap().is_empty(),
            "/{path}: the data is not given out as an attribute of itself"
        );
    }

    // The folder, whose records are in its inode as well.
    let sub = fs.lookup_path("sub").unwrap().unwrap();
    assert!(sub.is_inline(), "a small folder is in its inode too");
    let inside = fs.read_dir(&sub).unwrap();
    assert_eq!(inside.len(), 1, "neither . nor .. is a record of its own");
    assert_eq!(inside[0].name, b"inside.txt");

    // And one too long for an inode is in blocks, as it always was.
    let big = fs.lookup_path("big.bin").unwrap().unwrap();
    assert!(!big.is_inline());
    assert!(big.blocks > 0);
    let mut read = Vec::new();
    fs.file(&big).unwrap().read_to_end(&mut read).unwrap();
    assert_eq!(read, pattern(5000, 11));
}

/// A file system in a partition of a disk image, which is the three layers
/// this is the third of: a container holds a disk, the disk's table names
/// partitions, and a partition holds a file system.
#[test]
fn a_file_system_in_a_partition_of_a_card_is_read_through_it() {
    let Some(mkfs) = tool("mkfs.ext4") else {
        eprintln!("mkfs.ext4 cannot be run here: the layering is not checked");
        return;
    };
    let s = Scratch::new("in a partition");
    let from = s.0.join("tree");
    std::fs::create_dir_all(&from).unwrap();
    std::fs::write(from.join("hello.txt"), b"in a partition\n").unwrap();
    let inner = s.0.join("fs.img");
    std::fs::write(&inner, vec![0u8; 16 << 20]).unwrap();
    run(
        &mkfs,
        &[
            "-q",
            "-F",
            "-b",
            "1024",
            "-d",
            from.to_str().unwrap(),
            inner.to_str().unwrap(),
        ],
    );
    let fs_raw = std::fs::read(&inner).unwrap();

    // A card of one partition, beginning at sector 2048 as every tool
    // writes it, of type 0x83 as every Linux file system is.
    let start = 2048u32;
    let sectors = (fs_raw.len() / 512) as u32;
    let mut card = vec![0u8; (start as usize + sectors as usize) * 512];
    card[510..512].copy_from_slice(&[0x55, 0xAA]);
    let entry = 446;
    card[entry + 4] = 0x83;
    card[entry + 8..entry + 12].copy_from_slice(&start.to_le_bytes());
    card[entry + 12..entry + 16].copy_from_slice(&sectors.to_le_bytes());
    let at = start as usize * 512;
    card[at..at + fs_raw.len()].copy_from_slice(&fs_raw);

    let found = partitions(&card).unwrap().unwrap();
    assert_eq!(found.table, Table::Mbr);
    assert_eq!(found.partitions[0].kind.says(), Some("Linux file system"));
    let part = Part::new(&card, found.partitions[0].at, found.partitions[0].size);
    let fs = Ext::open(&part).unwrap();
    let node = fs.lookup_path("hello.txt").unwrap().unwrap();
    let mut data = Vec::new();
    fs.file(&node).unwrap().read_to_end(&mut data).unwrap();
    assert_eq!(data, b"in a partition\n");
}

/// The extended attributes of an inode, which is where a system keeps a
/// file's SELinux label, the capabilities a program is given and its access
/// control lists.
///
/// `debugfs` is what sets them here, because `setfattr` is not installed
/// everywhere and `mke2fs -d` can only copy what the folder it is given
/// already has. What it writes always goes in a block of its own, never in
/// the room left over in the inode — so this checks the block, and the file
/// systems built by hand below check the room in the inode.
#[test]
#[cfg(unix)]
fn the_extended_attributes_of_an_inode_are_read() {
    let Some(mkfs) = tool("mkfs.ext4") else {
        eprintln!("mkfs.ext4 cannot be run here: extended attributes are not checked against it");
        return;
    };
    let Some(debugfs) = tool("debugfs") else {
        eprintln!("debugfs cannot be run here: extended attributes are not checked against it");
        return;
    };
    let s = Scratch::new("xattrs");
    let from = s.0.join("tree");
    std::fs::create_dir_all(&from).unwrap();
    std::fs::write(from.join("a.txt"), b"one\n").unwrap();
    std::fs::write(from.join("b.txt"), b"two\n").unwrap();
    let image = s.0.join("fs.img");
    std::fs::write(&image, vec![0u8; 16 << 20]).unwrap();
    run(
        &mkfs,
        &[
            "-q",
            "-F",
            "-b",
            "1024",
            "-I",
            "256",
            "-d",
            from.to_str().unwrap(),
            image.to_str().unwrap(),
        ],
    );

    // A value of 300 bytes fits in a block and not in an inode, and one of
    // a few bytes would fit either way; `debugfs` puts both in a block.
    let long = "L".repeat(300);
    let want: Vec<(&str, &str, String)> = vec![
        ("a.txt", "user.comment", "a_small_value".to_owned()),
        (
            "a.txt",
            "security.selinux",
            "unconfined_u:object_r:user_home_t:s0".to_owned(),
        ),
        ("b.txt", "user.big", long.clone()),
    ];
    let big = s.0.join("big.val");
    std::fs::write(&big, &long).unwrap();
    for (path, name, value) in &want {
        // A long value is given as a file, as its own argument would be.
        let args: Vec<String> = if value.len() > 100 {
            vec![
                "-w".into(),
                "-R".into(),
                format!("ea_set -f {} /{path} {name}", big.to_str().unwrap()),
                image.to_str().unwrap().into(),
            ]
        } else {
            vec![
                "-w".into(),
                "-R".into(),
                format!("ea_set /{path} {name} {value}"),
                image.to_str().unwrap().into(),
            ]
        };
        let borrowed: Vec<&str> = args.iter().map(String::as_str).collect();
        run(&debugfs, &borrowed);
    }

    let raw = std::fs::read(&image).unwrap();
    let fs = Ext::open(&raw).unwrap();
    for path in ["a.txt", "b.txt"] {
        let node = fs.lookup_path(path).unwrap().unwrap();
        let mine = fs.xattrs(&node).unwrap();
        let mut want_here: Vec<(Vec<u8>, Vec<u8>)> = want
            .iter()
            .filter(|(at, _, _)| *at == path)
            .map(|(_, name, value)| (name.as_bytes().to_vec(), value.as_bytes().to_vec()))
            .collect();
        let mut got: Vec<(Vec<u8>, Vec<u8>)> = mine
            .iter()
            .map(|x| (x.name.clone(), x.value.clone()))
            .collect();
        want_here.sort();
        got.sort();
        assert_eq!(got, want_here, "/{path}: the attributes that were set");

        // What `debugfs` reads of the same inode, which is its own reader
        // of the same bytes: the names it lists, in its own order.
        let (ok, told) = said(
            &debugfs,
            &["-R", &format!("ea_list /{path}"), image.to_str().unwrap()],
        );
        assert!(ok, "debugfs could not list /{path}: {told}");
        // It writes each attribute on a line of its own, indented, which
        // is what tells them from the version it says first.
        let mut theirs: Vec<String> = told
            .lines()
            .filter(|line| line.starts_with(' '))
            .filter_map(|line| line.trim().split_once(" ("))
            .map(|(name, _)| name.to_owned())
            .collect();
        theirs.sort();
        let mut names: Vec<String> = mine.iter().map(|x| x.name_text().into_owned()).collect();
        names.sort();
        assert_eq!(names, theirs, "/{path}: the names debugfs lists");

        // And one value it reads with its own reader, for the one that is
        // short enough to come back unescaped.
        if path == "a.txt" {
            let (ok, told) = said(
                &debugfs,
                &[
                    "-R",
                    &format!("ea_get /{path} user.comment"),
                    image.to_str().unwrap(),
                ],
            );
            assert!(ok, "{told}");
            assert!(
                told.contains("\"a_small_value\""),
                "debugfs reads the value this reads: {told}"
            );
        }
    }
    // An inode with none has none, and is not an error.
    let root = fs.root().unwrap();
    assert!(fs.xattrs(&root).unwrap().is_empty());
    assert!(fs.xattr(&root, "user.nothing").unwrap().is_none());
}

// --- File systems built byte by byte --------------------------------------

/// What a file system built here is made of: one block group, blocks of
/// 1 KiB, and the layout `mke2fs` writes for one — block 0 is the room in
/// front of the superblock, 1 the superblock, 2 the group descriptors, 3
/// the block bitmap, 4 the inode bitmap, and then the inode table.
///
/// The numbers are the ones `mke2fs` writes, so that `e2fsck` has nothing
/// to say about them: it is run over every file system built here, and that
/// is what makes this half worth having.
const BLOCK: u32 = 1024;
const BLOCKS: u32 = 1024;
const INODES: u32 = 64;
/// How many of each a group holds, which for blocks is as many bits as a
/// block has.
const PER_GROUP: u32 = 8 * BLOCK;
/// The first inode a file may have; 11 is the one `mke2fs` gives
/// `lost+found`, which `e2fsck` wants to find.
const LOST_FOUND: u32 = 11;
const FIRST_INO: u32 = 11;

struct Build {
    inode_size: u32,
    /// Whether a file's blocks are found through a tree of extents, which
    /// is ext4, or through the numbers in the inode, which is ext2.
    extents: bool,
    image: Vec<u8>,
    next_block: u32,
    next_ino: u32,
    /// Whether anything in it keeps its data in its own inode, which the
    /// file system has to say in its features before `e2fsck` allows it.
    inline_used: bool,
    /// How many directories it holds, which the group descriptor says and
    /// `e2fsck` counts for itself.
    dirs: u16,
}

/// What an inode is to say about itself.
struct Which {
    mode: u16,
    size: u64,
    links: u16,
    /// Where each logical block of the data is: `None` for a hole.
    at: Vec<Option<u32>>,
    /// For a short symbolic link, the target, which goes where the block
    /// numbers would.
    inline: Option<Vec<u8>>,
}

impl Build {
    fn new(inode_size: u32, extents: bool) -> Build {
        let itable = (INODES * inode_size).div_ceil(BLOCK);
        let first_data = 5 + itable;
        Build {
            inode_size,
            extents,
            image: vec![0u8; (BLOCKS * BLOCK) as usize],
            next_block: first_data,
            next_ino: FIRST_INO + 1,
            inline_used: false,
            dirs: 0,
        }
    }

    /// The next block nothing is in.
    fn alloc(&mut self) -> u32 {
        let block = self.next_block;
        assert!(block < BLOCKS, "the file system has no more blocks");
        self.next_block += 1;
        block
    }

    fn write(&mut self, block: u32, bytes: &[u8]) {
        let at = (block * BLOCK) as usize;
        self.image[at..at + bytes.len()].copy_from_slice(bytes);
    }

    /// A file of `bytes`, which is as many blocks as it takes.
    fn file(&mut self, bytes: &[u8]) -> u32 {
        let mut at = Vec::new();
        for piece in bytes.chunks(BLOCK as usize) {
            let block = self.alloc();
            self.write(block, piece);
            at.push(Some(block));
        }
        self.node(Which {
            mode: 0o100_644,
            size: bytes.len() as u64,
            links: 1,
            at,
            inline: None,
        })
    }

    /// A file with holes: `pieces` says which logical blocks hold what, and
    /// every block between them is a hole, which reads as zeroes.
    fn holey(&mut self, pieces: &[(u32, &[u8])], blocks: u32) -> u32 {
        let mut at = vec![None; blocks as usize];
        for (which, bytes) in pieces {
            let block = self.alloc();
            self.write(block, bytes);
            at[*which as usize] = Some(block);
        }
        self.node(Which {
            mode: 0o100_644,
            size: u64::from(blocks) * u64::from(BLOCK),
            links: 1,
            at,
            inline: None,
        })
    }

    /// A symbolic link. A target short enough goes in the inode itself,
    /// which is what every tool writes; a longer one takes a block.
    fn link(&mut self, to: &[u8]) -> u32 {
        let short = to.len() < 60;
        let at = if short {
            Vec::new()
        } else {
            let block = self.alloc();
            self.write(block, to);
            vec![Some(block)]
        };
        self.node(Which {
            mode: 0o120_777,
            size: to.len() as u64,
            links: 1,
            at,
            inline: short.then(|| to.to_vec()),
        })
    }

    /// A directory of `entries`, which is given `.` and `..` in front of
    /// them. `parent` is the inode of the directory it is in.
    fn dir(&mut self, ino: u32, parent: u32, entries: &[(&[u8], u32, u8)]) -> u32 {
        let block = self.alloc();
        let mut records: Vec<(&[u8], u32, u8)> = vec![(b".", ino, 2), (b"..", parent, 2)];
        records.extend_from_slice(entries);
        let raw = dir_block(&records);
        self.write(block, &raw);
        // A directory's links are its own `.`, its parent's record of it,
        // and one for each directory inside it.
        let links = 2 + entries.iter().filter(|(_, _, kind)| *kind == 2).count() as u16;
        self.write_node(
            ino,
            Which {
                mode: 0o40_755,
                size: u64::from(BLOCK),
                links,
                at: vec![Some(block)],
                inline: None,
            },
        );
        self.dirs += 1;
        ino
    }

    /// An inode of the next number there is.
    fn node(&mut self, which: Which) -> u32 {
        let ino = self.next_ino;
        self.next_ino += 1;
        assert!(ino <= INODES, "the file system has no more inodes");
        self.write_node(ino, which);
        ino
    }

    /// Writes one inode into the table.
    fn write_node(&mut self, ino: u32, which: Which) {
        let (map, meta) = match &which.inline {
            Some(bytes) => {
                let mut map = [0u8; 60];
                map[..bytes.len()].copy_from_slice(bytes);
                (map, 0)
            }
            None if self.extents => self.extent_map(&which.at),
            None => self.block_map(&which.at),
        };
        let held = which.at.iter().filter(|b| b.is_some()).count() as u32;
        // How many 512-byte blocks it takes: the data and the blocks that
        // say where the data is, which `e2fsck` adds up for itself.
        let blocks = (held + meta) * (BLOCK / 512);
        let mut raw = vec![0u8; self.inode_size as usize];
        put16(&mut raw, 0, which.mode);
        put16(&mut raw, 2, 1000);
        put32(&mut raw, 4, which.size as u32);
        for at in [8, 12, 16] {
            put32(&mut raw, at, 1_700_000_000);
        }
        put16(&mut raw, 24, 1000);
        put16(&mut raw, 26, which.links);
        put32(&mut raw, 28, blocks);
        if self.extents && which.inline.is_none() && !which.at.is_empty() {
            put32(&mut raw, 32, 0x8_0000);
        }
        raw[40..100].copy_from_slice(&map);
        if which.mode & 0xF000 == 0x8000 {
            put32(&mut raw, 108, (which.size >> 32) as u32);
        }
        if self.inode_size > 128 {
            // The fields past the 128 bytes every inode has: how much of
            // them was written, and the nanoseconds and the time it was
            // made, which only an inode with room keeps.
            put16(&mut raw, 128, 32);
            for at in [132, 136, 140] {
                // Two bits for what the seconds ran out of room for, and
                // the rest nanoseconds: 123456789 of them.
                put32(&mut raw, at, 123_456_789 << 2);
            }
            put32(&mut raw, 144, 1_600_000_000);
            put32(&mut raw, 148, 0);
        }
        let at = (5 * BLOCK) as usize + ((ino - 1) * self.inode_size) as usize;
        self.image[at..at + raw.len()].copy_from_slice(&raw);
    }

    /// The 60 bytes of an inode as the block numbers ext2 kept there, and
    /// how many blocks of numbers that took.
    fn block_map(&mut self, at: &[Option<u32>]) -> ([u8; 60], u32) {
        let per = (BLOCK / 4) as usize;
        let mut map = [0u8; 60];
        let mut meta = 0;
        for (i, block) in at.iter().take(12).enumerate() {
            put32(&mut map, i * 4, block.unwrap_or(0));
        }
        if at.len() > 12 {
            let single = self.alloc();
            meta += 1;
            put32(&mut map, 12 * 4, single);
            let mut raw = vec![0u8; BLOCK as usize];
            for (i, block) in at[12..].iter().take(per).enumerate() {
                put32(&mut raw, i * 4, block.unwrap_or(0));
            }
            self.write(single, &raw);
        }
        if at.len() > 12 + per {
            let double = self.alloc();
            meta += 1;
            put32(&mut map, 13 * 4, double);
            let mut top = vec![0u8; BLOCK as usize];
            let rest: Vec<Option<u32>> = at[12 + per..].to_vec();
            for (j, piece) in rest.chunks(per).enumerate() {
                let mid = self.alloc();
                meta += 1;
                put32(&mut top, j * 4, mid);
                let mut raw = vec![0u8; BLOCK as usize];
                for (i, block) in piece.iter().enumerate() {
                    put32(&mut raw, i * 4, block.unwrap_or(0));
                }
                self.write(mid, &raw);
            }
            self.write(double, &top);
        }
        (map, meta)
    }

    /// The same as a tree of extents: one for each run of blocks that
    /// follow one another, in the inode where they fit and in a node of
    /// their own where they do not.
    fn extent_map(&mut self, at: &[Option<u32>]) -> ([u8; 60], u32) {
        let mut runs: Vec<(u32, u32, u32)> = Vec::new();
        for (i, block) in at.iter().enumerate() {
            let Some(block) = block else { continue };
            match runs.last_mut() {
                Some((first, start, len))
                    if *first + *len == i as u32 && *start + *len == *block =>
                {
                    *len += 1;
                }
                _ => runs.push((i as u32, *block, 1)),
            }
        }
        let mut map = [0u8; 60];
        let in_inode = (60 - 12) / 12;
        if runs.len() <= in_inode {
            extent_header(&mut map, runs.len() as u16, in_inode as u16, 0);
            for (i, run) in runs.iter().enumerate() {
                extent(&mut map, 12 + i * 12, *run);
            }
            return (map, 0);
        }
        // More runs than the inode has room for: a node of its own, which
        // the inode points at.
        let leaf = self.alloc();
        let room = (BLOCK as usize - 12) / 12;
        assert!(runs.len() <= room, "more extents than a node holds");
        let mut raw = vec![0u8; BLOCK as usize];
        extent_header(&mut raw, runs.len() as u16, room as u16, 0);
        for (i, run) in runs.iter().enumerate() {
            extent(&mut raw, 12 + i * 12, *run);
        }
        self.write(leaf, &raw);
        extent_header(&mut map, 1, in_inode as u16, 1);
        put32(&mut map, 12, runs[0].0);
        put32(&mut map, 16, leaf);
        (map, 1)
    }

    /// A file whose data is in its own inode: the 60 bytes where the block
    /// numbers would be, and the rest in the attribute the file system
    /// keeps it in.
    fn inline_file(&mut self, bytes: &[u8]) -> u32 {
        let head = &bytes[..bytes.len().min(60)];
        let ino = self.node(Which {
            mode: 0o100_644,
            size: bytes.len() as u64,
            links: 1,
            at: Vec::new(),
            inline: Some(head.to_vec()),
        });
        self.says_inline(ino);
        // Even one that fits says so with an attribute of no bytes, which
        // is what `mke2fs` writes.
        let rest = if bytes.len() > 60 {
            &bytes[60..]
        } else {
            &[][..]
        };
        self.xattrs_in_inode(ino, &[(7, b"data", rest)]);
        ino
    }

    /// A directory whose records are in its own inode: four bytes holding
    /// the inode it is in, which stand for its `..`, and then the records.
    /// Its `.` is written nowhere at all.
    fn inline_dir(&mut self, ino: u32, parent: u32, entries: &[(&[u8], u32, u8)]) {
        let mut map = vec![0u8; 60];
        put32(&mut map, 0, parent);
        map[4..].copy_from_slice(&dir_records(entries, 60 - 4));
        let links = 2 + entries.iter().filter(|(_, _, kind)| *kind == 2).count() as u16;
        self.write_node(
            ino,
            Which {
                mode: 0o40_755,
                size: 60,
                links,
                at: Vec::new(),
                inline: Some(map),
            },
        );
        self.says_inline(ino);
        self.xattrs_in_inode(ino, &[(7, b"data", &[])]);
        self.dirs += 1;
    }

    /// Says of an inode that its data is in itself.
    fn says_inline(&mut self, ino: u32) {
        self.inline_used = true;
        let at = (5 * BLOCK + (ino - 1) * self.inode_size) as usize;
        put32(&mut self.image, at + 32, 0x1000_0000);
    }

    /// Extended attributes in the room left over in the inode, which is
    /// where the ones that fit go.
    ///
    /// An entry kept in an inode carries no hash: the file system hashes
    /// only the ones in a block, which it may then share between inodes.
    fn xattrs_in_inode(&mut self, ino: u32, attrs: &[(u8, &[u8], &[u8])]) {
        assert!(self.inode_size > 128, "a 128-byte inode has no room left");
        let at = (5 * BLOCK + (ino - 1) * self.inode_size) as usize;
        let size = self.inode_size as usize;
        let mut room = self.image[at..at + size].to_vec();
        // What `write_node` wrote for how much of the inode was written.
        let from = 128 + 32;
        put32(&mut room, from, XATTR_MAGIC);
        let first = from + 4;
        let (mut entry, mut value) = (first, size);
        for (index, name, bytes) in attrs {
            value -= bytes.len().next_multiple_of(4);
            assert!(
                entry + 16 + name.len() + 4 <= value,
                "no room in the inode for the attributes"
            );
            // Inside an inode, where the value is, is counted from the
            // first entry rather than from the start of the room, and
            // nothing kept in an inode is hashed.
            one_xattr(&mut room, entry, (*index, name, bytes), value, first, false);
            entry += (16 + name.len()).next_multiple_of(4);
        }
        self.image[at..at + size].copy_from_slice(&room);
    }

    /// Extended attributes in a block of their own, which is where the ones
    /// that do not fit in the inode go. Each is hashed, and the block holds
    /// a hash of the hashes, both of which `e2fsck` checks.
    fn xattrs_in_block(&mut self, ino: u32, attrs: &[(u8, &[u8], &[u8])]) {
        let block = self.alloc();
        let mut raw = vec![0u8; BLOCK as usize];
        put32(&mut raw, 0, XATTR_MAGIC);
        // One inode points at it, and it is one block long.
        put32(&mut raw, 4, 1);
        put32(&mut raw, 8, 1);
        let (mut entry, mut value) = (32usize, BLOCK as usize);
        let mut block_hash = 0u32;
        for (index, name, bytes) in attrs {
            value -= bytes.len().next_multiple_of(4);
            assert!(
                entry + 16 + name.len() + 4 <= value,
                "no room in a block for the attributes"
            );
            let hash = one_xattr(&mut raw, entry, (*index, name, bytes), value, 0, true);
            block_hash = block_hash.rotate_left(16) ^ hash;
            entry += (16 + name.len()).next_multiple_of(4);
        }
        put32(&mut raw, 16, block_hash);
        self.write(block, &raw);
        // The inode points at the block, and counts it among the blocks it
        // takes, which `e2fsck` adds up for itself.
        let at = (5 * BLOCK + (ino - 1) * self.inode_size) as usize;
        put32(&mut self.image, at + 104, block);
        let blocks = get32(&self.image, at + 28) + BLOCK / 512;
        put32(&mut self.image, at + 28, blocks);
    }

    /// The superblock, the group descriptor and the two bitmaps, once
    /// everything else is in: the whole image.
    fn finish(mut self) -> Vec<u8> {
        let used_inodes = self.next_ino - 1;
        // The block bitmap: one bit for each block of the group, which
        // begins at block 1, and every bit past the end of the file system
        // set, as `e2fsck` expects.
        let mut blocks = vec![0u8; BLOCK as usize];
        for block in 1..self.next_block {
            let i = (block - 1) as usize;
            blocks[i / 8] |= 1 << (i % 8);
        }
        for i in (BLOCKS - 1) as usize..PER_GROUP as usize {
            blocks[i / 8] |= 1 << (i % 8);
        }
        self.write(3, &blocks);
        // The inode bitmap: the inodes handed out, the ten the file system
        // keeps for itself, and everything past the end.
        let mut inodes = vec![0u8; BLOCK as usize];
        for ino in 1..=used_inodes {
            let i = (ino - 1) as usize;
            inodes[i / 8] |= 1 << (i % 8);
        }
        for i in INODES as usize..PER_GROUP as usize {
            inodes[i / 8] |= 1 << (i % 8);
        }
        self.write(4, &inodes);

        let free_blocks = BLOCKS - self.next_block;
        let free_inodes = INODES - used_inodes;
        // The group descriptor: where the bitmaps and the table are, and
        // what is left over.
        let mut group = vec![0u8; 32];
        put32(&mut group, 0, 3);
        put32(&mut group, 4, 4);
        put32(&mut group, 8, 5);
        put16(&mut group, 12, free_blocks as u16);
        put16(&mut group, 14, free_inodes as u16);
        put16(&mut group, 16, self.dirs);
        self.write(2, &group);

        let mut sb = vec![0u8; BLOCK as usize];
        put32(&mut sb, 0, INODES);
        put32(&mut sb, 4, BLOCKS);
        put32(&mut sb, 12, free_blocks);
        put32(&mut sb, 16, free_inodes);
        put32(&mut sb, 20, 1);
        put32(&mut sb, 32, PER_GROUP);
        put32(&mut sb, 36, PER_GROUP);
        put32(&mut sb, 40, INODES);
        put32(&mut sb, 44, 1_700_000_000);
        put32(&mut sb, 48, 1_700_000_000);
        put16(&mut sb, 56, 0xEF53);
        // Clean, and errors are to be ignored rather than acted on.
        put16(&mut sb, 58, 1);
        put16(&mut sb, 60, 1);
        put16(&mut sb, 54, 0xFFFF);
        put32(&mut sb, 64, 1_700_000_000);
        put32(&mut sb, 76, 1);
        put32(&mut sb, 84, FIRST_INO);
        put16(&mut sb, 88, self.inode_size as u16);
        // What it says it needs: records that say what they name, and
        // extents where the files are mapped that way. Nothing else, so
        // that what is read is the oldest layout there is.
        // What it may have, which a reader need not know to read it: that
        // inodes may have extended attributes. Without it `e2fsck` calls
        // the block an inode points at for them rubbish, and will not
        // count it among the blocks the inode takes either.
        put32(&mut sb, 92, 0x8);
        put32(
            &mut sb,
            96,
            0x2 | if self.extents { 0x40 } else { 0 } | if self.inline_used { 0x8000 } else { 0 },
        );
        put32(&mut sb, 100, 0x1);
        for (i, byte) in (0u8..16).enumerate() {
            sb[104 + i] = byte | 0x40;
        }
        sb[120..128].copy_from_slice(b"BY HAND\0");
        put32(&mut sb, 264, 1_700_000_000);
        // The superblock is 1024 bytes in, which with blocks of 1 KiB is
        // block 1.
        self.image[1024..1024 + sb.len()].copy_from_slice(&sb);
        self.image
    }
}

/// One block of directory records, the last of them reaching to the end of
/// the block as the format says it must.
fn dir_block(entries: &[(&[u8], u32, u8)]) -> Vec<u8> {
    dir_records(entries, BLOCK as usize)
}

/// Directory records filling `room_for` bytes, the last of them reaching to
/// the end of it as the format says it must: one block of a directory, or
/// the room inside an inode that holds one.
fn dir_records(entries: &[(&[u8], u32, u8)], room_for: usize) -> Vec<u8> {
    let mut raw = vec![0u8; room_for];
    let mut at = 0usize;
    for (i, (name, ino, kind)) in entries.iter().enumerate() {
        let need = (8 + name.len()).next_multiple_of(4);
        let room = if i + 1 == entries.len() {
            room_for - at
        } else {
            need
        };
        assert!(at + need <= room_for, "more records than there is room for");
        put32(&mut raw, at, *ino);
        put16(&mut raw, at + 4, room as u16);
        raw[at + 6] = name.len() as u8;
        raw[at + 7] = *kind;
        raw[at + 8..at + 8 + name.len()].copy_from_slice(name);
        at += room;
    }
    raw
}

/// The header every node of a tree of extents begins with.
fn extent_header(raw: &mut [u8], entries: u16, max: u16, depth: u16) {
    put16(raw, 0, 0xF30A);
    put16(raw, 2, entries);
    put16(raw, 4, max);
    put16(raw, 6, depth);
}

/// One extent: which logical block it begins at, where it is, and how long.
fn extent(raw: &mut [u8], at: usize, (first, start, len): (u32, u32, u32)) {
    put32(raw, at, first);
    put16(raw, at + 4, len as u16);
    put16(raw, at + 6, 0);
    put32(raw, at + 8, start);
}

/// What a region of extended attributes begins with.
const XATTR_MAGIC: u32 = 0xEA02_0000;

/// One entry at `at`, with its value at `value_at`. What the entry says
/// about where its value is, is counted from `base`: the first entry inside
/// an inode, and the start of the block in a block.
///
/// `hashed` says whether to hash it, which only a block's entries are, and
/// what comes back is the hash written, so that a block's own hash of its
/// hashes can be built out of them.
fn one_xattr(
    raw: &mut [u8],
    at: usize,
    (index, name, value): (u8, &[u8], &[u8]),
    value_at: usize,
    base: usize,
    hashed: bool,
) -> u32 {
    let hash = if hashed { xattr_hash(name, value) } else { 0 };
    raw[at] = name.len() as u8;
    raw[at + 1] = index;
    put16(raw, at + 2, (value_at - base) as u16);
    put32(raw, at + 8, value.len() as u32);
    put32(raw, at + 12, hash);
    raw[at + 16..at + 16 + name.len()].copy_from_slice(name);
    raw[value_at..value_at + value.len()].copy_from_slice(value);
    hash
}

/// The hash of one entry, as e2fsprogs computes it: the name a shift at a
/// time, and then the value four bytes at a time, read as the little-endian
/// numbers they lie as.
fn xattr_hash(name: &[u8], value: &[u8]) -> u32 {
    let mut hash = 0u32;
    for byte in name {
        hash = hash.rotate_left(5) ^ u32::from(*byte);
    }
    if !value.is_empty() {
        let mut padded = value.to_vec();
        padded.resize(value.len().next_multiple_of(4), 0);
        for four in padded.as_chunks::<4>().0 {
            hash = hash.rotate_left(16) ^ u32::from_le_bytes(*four);
        }
    }
    hash
}

fn get32(raw: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(raw[at..at + 4].try_into().unwrap())
}

fn put16(raw: &mut [u8], at: usize, value: u16) {
    raw[at..at + 2].copy_from_slice(&value.to_le_bytes());
}

fn put32(raw: &mut [u8], at: usize, value: u32) {
    raw[at..at + 4].copy_from_slice(&value.to_le_bytes());
}

/// What the file systems built here keep beside their inodes: two in the
/// room left over in the inode of `hello.txt`, where the ones that fit go,
/// and two in a block of their own for `big.bin`, the first of them longer
/// than any inode could have held.
const IN_INODE: [(u8, &[u8], &[u8]); 2] = [(1, b"comment", b"small"), (4, b"thing", b"x")];
const BIG: [u8; 300] = [b'L'; 300];
const SELINUX: &[u8] = b"unconfined_u:object_r:user_home_t:s0";

/// A file system with one of everything in it, built byte by byte.
fn by_hand(inode_size: u32, extents: bool) -> (Vec<u8>, BTreeMap<Vec<u8>, Thing>) {
    let mut build = Build::new(inode_size, extents);
    let mut want: BTreeMap<Vec<u8>, Thing> = BTreeMap::new();

    let short = b"a few bytes\n".to_vec();
    let hello = build.file(&short);
    want.insert(b"hello.txt".to_vec(), Thing::File(short));
    // Attributes in the room left over in the inode, where it has any.
    if inode_size > 128 {
        build.xattrs_in_inode(hello, &IN_INODE);
    }

    // Longer than the twelve numbers an inode holds and longer than one
    // block of numbers after them, so that all three levels of the map are
    // read; as a tree of extents it is one extent.
    let big = pattern(300 * BLOCK as usize, 5);
    let big_ino = build.file(&big);
    want.insert(b"big.bin".to_vec(), Thing::File(big));
    // And attributes in a block of their own, which is where the ones too
    // long for an inode go.
    build.xattrs_in_block(big_ino, &[(1, b"big", &BIG), (6, b"selinux", SELINUX)]);

    // A file of holes with three pieces in it, which is three extents.
    let piece = pattern(BLOCK as usize, 9);
    let holey = build.holey(&[(0, &piece), (60, &piece), (400, &piece)], 500);
    let mut whole = vec![0u8; 500 * BLOCK as usize];
    for at in [0usize, 60, 400] {
        whole[at * BLOCK as usize..(at + 1) * BLOCK as usize].copy_from_slice(&piece);
    }
    want.insert(b"holes.bin".to_vec(), Thing::File(whole));

    // Six pieces, which is more extents than an inode has room for: a tree
    // of a depth of its own, and on the other side six runs of the map.
    let deep = build.holey(
        &[
            (0, &piece),
            (2, &piece),
            (4, &piece),
            (6, &piece),
            (8, &piece),
            (10, &piece),
        ],
        12,
    );
    let mut whole = vec![0u8; 12 * BLOCK as usize];
    for at in [0usize, 2, 4, 6, 8, 10] {
        whole[at * BLOCK as usize..(at + 1) * BLOCK as usize].copy_from_slice(&piece);
    }
    want.insert(b"pieces.bin".to_vec(), Thing::File(whole));

    // Both kinds of symbolic link.
    let long = b"/a/very/long/target/that/will/not/fit/in/the/sixty/bytes/of/the/inode".to_vec();
    let fast = build.link(b"hello.txt");
    let slow = build.link(&long);
    want.insert(b"link".to_vec(), Thing::Link(b"hello.txt".to_vec()));
    want.insert(b"longlink".to_vec(), Thing::Link(long));

    // A name that is not UTF-8, which Linux allows and text does not.
    let odd = build.file(b"bytes are bytes\n");
    want.insert(
        b"not\xffutf8.txt".to_vec(),
        Thing::File(b"bytes are bytes\n".to_vec()),
    );

    // A directory inside the root, with a file in it.
    let inside = build.file(b"in a folder\n");
    let sub = build.next_ino;
    build.next_ino += 1;
    build.dir(sub, 2, &[(b"inside.txt", inside, 1)]);
    want.insert(b"sub".to_vec(), Thing::Dir);
    want.insert(
        b"sub/inside.txt".to_vec(),
        Thing::File(b"in a folder\n".to_vec()),
    );

    // What `e2fsck` wants every file system to have.
    build.dir(LOST_FOUND, 2, &[]);
    want.insert(b"lost+found".to_vec(), Thing::Dir);

    let mut root: Vec<(&[u8], u32, u8)> = vec![
        (b"lost+found", LOST_FOUND, 2),
        (b"hello.txt", hello, 1),
        (b"big.bin", big_ino, 1),
        (b"holes.bin", holey, 1),
        (b"pieces.bin", deep, 1),
        (b"link", fast, 7),
        (b"longlink", slow, 7),
        (b"not\xffutf8.txt", odd, 1),
        (b"sub", sub, 2),
    ];

    // Things small enough to be in their own inodes, where the inode has
    // room left over to put them in: one that fits in the 60 bytes the
    // block numbers would take, one that needs the attribute as well, and
    // a folder, whose records go there in one run.
    if extents && inode_size > 128 {
        let small = b"small enough for the inode\n".to_vec();
        let tiny = build.inline_file(&small);
        want.insert(b"tiny.txt".to_vec(), Thing::File(small));
        let spread = pattern(90, 13);
        let mid = build.inline_file(&spread);
        want.insert(b"mid.bin".to_vec(), Thing::File(spread));
        let held = b"in a folder in an inode\n".to_vec();
        let in_folder = build.inline_file(&held);
        let folder = build.next_ino;
        build.next_ino += 1;
        build.inline_dir(folder, 2, &[(b"in.txt", in_folder, 1)]);
        want.insert(b"inline".to_vec(), Thing::Dir);
        want.insert(b"inline/in.txt".to_vec(), Thing::File(held));
        root.push((b"tiny.txt", tiny, 1));
        root.push((b"mid.bin", mid, 1));
        root.push((b"inline", folder, 2));
    }

    build.dir(2, 2, &root);
    (build.finish(), want)
}

#[test]
fn a_file_system_built_by_hand_reads_as_it_was_built() {
    for (inode_size, extents) in [(128, false), (256, false), (256, true), (512, true)] {
        let how = if extents { "extents" } else { "block numbers" };
        let what = format!("{inode_size}-byte inodes, {how}");
        let (image, want) = by_hand(inode_size, extents);
        sound(&what, &image);
        let fs = Ext::open(&image)
            .map_err(|e| format!("{what}: {e}"))
            .unwrap();
        assert_eq!(
            fs.kind(),
            if extents { Kind::Ext4 } else { Kind::Ext2 },
            "{what}"
        );
        assert_eq!(fs.label(), Some("BY HAND"), "{what}");
        assert_eq!(fs.block_size(), BLOCK, "{what}");
        assert_eq!(what_it_holds(&fs), want, "{what}");

        // The times, and the nanoseconds an inode with room for them keeps.
        let node = fs.lookup_path("hello.txt").unwrap().unwrap();
        let at = node.modified.unwrap();
        assert_eq!(at.seconds, 1_700_000_000, "{what}");
        assert_eq!(
            at.nanoseconds,
            if inode_size > 128 { 123_456_789 } else { 0 },
            "{what}: nanoseconds are kept past the first 128 bytes"
        );
        assert_eq!(
            node.created.map(|t| t.seconds),
            (inode_size > 128).then_some(1_600_000_000),
            "{what}: when it was made is kept there too"
        );
        assert_eq!(
            (node.uid, node.gid, node.mode),
            (1000, 1000, 0o644),
            "{what}"
        );

        // The attributes in the room left over in the inode. A 128-byte
        // inode has none to leave over, so it carries none.
        let held: Vec<(Vec<u8>, Vec<u8>)> = fs
            .xattrs(&node)
            .unwrap()
            .into_iter()
            .map(|one| (one.name, one.value))
            .collect();
        let wanted: Vec<(Vec<u8>, Vec<u8>)> = if inode_size > 128 {
            vec![
                (b"user.comment".to_vec(), b"small".to_vec()),
                (b"trusted.thing".to_vec(), b"x".to_vec()),
            ]
        } else {
            Vec::new()
        };
        assert_eq!(held, wanted, "{what}: kept in the inode");

        // And the ones in a block of their own, the first of them longer
        // than an inode could have held.
        let big = fs.lookup_path("big.bin").unwrap().unwrap();
        let held: Vec<(Vec<u8>, Vec<u8>)> = fs
            .xattrs(&big)
            .unwrap()
            .into_iter()
            .map(|one| (one.name, one.value))
            .collect();
        assert_eq!(
            held,
            vec![
                (b"user.big".to_vec(), BIG.to_vec()),
                (b"security.selinux".to_vec(), SELINUX.to_vec()),
            ],
            "{what}: kept in a block"
        );
        assert_eq!(
            fs.xattr(&big, "security.selinux").unwrap().as_deref(),
            Some(SELINUX),
            "{what}: one by name"
        );
        assert!(fs.xattr(&big, "user.nothing").unwrap().is_none(), "{what}");

        // What is kept in its own inode, where the inode has room: the
        // whole tree above already compared their bytes, so what is left
        // to say is that they are really kept there.
        if extents && inode_size > 128 {
            for path in ["tiny.txt", "mid.bin", "inline", "inline/in.txt"] {
                let node = fs.lookup_path(path).unwrap().unwrap();
                assert!(node.is_inline(), "{what}: /{path} is in its inode");
                assert_eq!(node.blocks, 0, "{what}: /{path} is given no blocks");
                assert!(
                    fs.xattrs(&node).unwrap().is_empty(),
                    "{what}: /{path} does not give its own data out as an attribute"
                );
            }
        }
    }
}

#[test]
fn a_path_is_looked_up_by_the_bytes_of_its_names() {
    let (image, _) = by_hand(256, true);
    let fs = Ext::open(&image).unwrap();
    for path in ["hello.txt", "/hello.txt", "./hello.txt", "sub/inside.txt"] {
        assert!(fs.lookup_path(path).unwrap().is_some(), "{path}");
    }
    // Bytes, not text: a name that is not UTF-8 is looked up as it is.
    assert!(fs.lookup_path(b"not\xffutf8.txt").unwrap().is_some());
    // And case is case, where FAT would have found it either way.
    assert!(fs.lookup_path("HELLO.TXT").unwrap().is_none());
    assert!(fs.lookup_path("nowhere").unwrap().is_none());
    assert!(fs.lookup_path("hello.txt/more").unwrap().is_none());
    // The root itself, which every path begins at.
    let root = fs.lookup_path("/").unwrap().unwrap();
    assert_eq!(root.ino, 2);
    assert!(root.is_dir());
}

#[test]
fn what_a_thing_is_not_is_refused() {
    let (image, _) = by_hand(256, true);
    let fs = Ext::open(&image).unwrap();
    let dir = fs.lookup_path("sub").unwrap().unwrap();
    let file = fs.lookup_path("hello.txt").unwrap().unwrap();
    let link = fs.lookup_path("link").unwrap().unwrap();
    assert!(matches!(fs.file(&dir), Err(Error::NotAFile)));
    assert!(matches!(fs.read_dir(&file), Err(Error::NotADirectory)));
    assert!(matches!(fs.read_link(&file), Err(Error::NotALink)));
    assert!(fs.read_link(&link).is_ok());
    assert!(matches!(fs.node(0), Err(Error::NoSuchInode { ino: 0 })));
    assert!(matches!(
        fs.node(INODES + 1),
        Err(Error::NoSuchInode { .. })
    ));
}

#[test]
fn a_file_reads_the_same_in_pieces_of_any_size() {
    use std::io::{Seek, SeekFrom};

    let (image, want) = by_hand(256, true);
    let fs = Ext::open(&image).unwrap();
    let Thing::File(bytes) = &want[b"holes.bin".as_slice()] else {
        unreachable!("holes.bin is a file")
    };
    let node = fs.lookup_path("holes.bin").unwrap().unwrap();
    for piece in [1usize, 7, 1023, 1024, 1025, 4096, 100_003] {
        let mut file = fs.file(&node).unwrap();
        let mut data = Vec::new();
        let mut buf = vec![0u8; piece];
        loop {
            let read = file.read(&mut buf).unwrap();
            if read == 0 {
                break;
            }
            data.extend_from_slice(&buf[..read]);
        }
        assert_eq!(&data, bytes, "in pieces of {piece}");
    }
    let mut file = fs.file(&node).unwrap();
    assert_eq!(file.len(), bytes.len() as u64);
    // Into a hole, and into the piece at the end.
    file.seek(SeekFrom::Start(30 * u64::from(BLOCK))).unwrap();
    let mut hole = vec![0u8; 64];
    file.read_exact(&mut hole).unwrap();
    assert!(hole.iter().all(|b| *b == 0), "a hole reads as zeroes");
    file.seek(SeekFrom::End(-1024)).unwrap();
    let mut end = Vec::new();
    file.read_to_end(&mut end).unwrap();
    assert_eq!(end, bytes[bytes.len() - 1024..]);
    assert!(file.seek(SeekFrom::Current(-1_000_000)).is_err());
}

/// The fields the first ext2 had no room for lie one after another in the
/// second half of the inode, two bytes each: how many blocks the file takes
/// at 116, where its extended attributes are at 118, the owner at 120, the
/// group at 122. Reading one of them where the next lies answers a number
/// that belongs to something else — and it stays hidden, because a file
/// system that needs neither high half writes zero in both.
///
/// So each is patched in and asked for by itself.
#[test]
fn the_high_halves_of_an_inode_are_read_where_each_lies() {
    let (image, _) = by_hand(256, true);
    let fs = Ext::open(&image).unwrap();
    let node = fs.lookup_path("hello.txt").unwrap().unwrap();
    let at = (5 * BLOCK + (node.ino - 1) * 256) as usize;
    let was = node.blocks;
    assert_eq!(
        fs.xattrs(&node).unwrap().len(),
        2,
        "two in the inode's room"
    );

    // How many blocks it takes, in the half at 116.
    let mut changed = image.clone();
    put16(&mut changed, at + 116, 1);
    let fs = Ext::open(&changed).unwrap();
    let node = fs.lookup_path("hello.txt").unwrap().unwrap();
    assert_eq!(node.blocks, was + (1 << 32), "the blocks are at 116");
    assert_eq!(fs.xattrs(&node).unwrap().len(), 2, "and nothing else moved");

    // Where its extended attributes are, in the half at 118: it says a
    // block the file system has not got, so asking for them says so — and
    // how many blocks the file takes is what it was.
    let mut changed = image.clone();
    put16(&mut changed, at + 118, 1);
    let fs = Ext::open(&changed).unwrap();
    let node = fs.lookup_path("hello.txt").unwrap().unwrap();
    assert_eq!(node.blocks, was, "the attributes are not the blocks");
    assert!(matches!(
        fs.xattrs(&node),
        Err(Error::PastTheEnd {
            block: 0x1_0000_0000
        })
    ));

    // And the owner and the group, in the halves after them.
    let mut changed = image.clone();
    put16(&mut changed, at + 120, 1);
    put16(&mut changed, at + 122, 2);
    let fs = Ext::open(&changed).unwrap();
    let node = fs.lookup_path("hello.txt").unwrap().unwrap();
    assert_eq!((node.uid, node.gid), (65_536 + 1000, 131_072 + 1000));
    assert_eq!(node.blocks, was);
}

#[test]
fn what_is_not_an_ext_file_system_is_told_from_one() {
    assert!(matches!(
        Ext::open(&vec![0u8; 1 << 20]),
        Err(Error::Unrecognized)
    ));
    assert!(matches!(Ext::open(&Vec::new()), Err(Error::Unrecognized)));
    // The signature and nothing else: no layout behind it.
    let mut only = vec![0u8; 1 << 20];
    put16(&mut only, 1024 + 56, 0xEF53);
    assert!(matches!(Ext::open(&only), Err(Error::Says)));
}

/// Layouts no file system has, and features that are refused, each of which
/// would otherwise be read as a tree that is not on the disk.
#[test]
fn a_layout_the_format_does_not_have_is_refused() {
    let (sound, _) = by_hand(256, true);
    assert!(Ext::open(&sound).is_ok());
    // The image is handed over rather than borrowed, so that what comes
    // back does not point into a copy that is already gone.
    let changed = |at: usize, bytes: &[u8]| {
        let mut image = sound.clone();
        image[1024 + at..1024 + at + bytes.len()].copy_from_slice(bytes);
        Ext::open(image)
    };
    let says = |at: usize, bytes: &[u8]| matches!(changed(at, bytes), Err(Error::Says));
    assert!(says(24, &7u32.to_le_bytes()), "a block of no such size");
    assert!(says(4, &0u32.to_le_bytes()), "no blocks");
    assert!(says(0, &0u32.to_le_bytes()), "no inodes");
    assert!(says(32, &0u32.to_le_bytes()), "groups of no blocks");
    assert!(says(40, &0u32.to_le_bytes()), "groups of no inodes");
    assert!(says(20, &5u32.to_le_bytes()), "data before the superblock");
    assert!(
        says(88, &64u16.to_le_bytes()),
        "an inode smaller than one is"
    );
    assert!(says(88, &3u16.to_le_bytes()), "an inode of no such size");
    assert!(says(4, &u32::MAX.to_le_bytes()), "longer than the disk");

    // The features that are refused, each as the superblock says it.
    for (bits, want) in [
        (0x0001u32, Unsupported::Compression),
        (0x0004, Unsupported::Journal),
        (0x0010, Unsupported::MetaGroups),
        (0x1_0000, Unsupported::Encrypted),
        (0x80_0000, Unsupported::Feature),
    ] {
        let incompat = 0x2u32 | 0x40 | bits;
        let got = changed(96, &incompat.to_le_bytes());
        assert!(
            matches!(&got, Err(Error::Needs(needs)) if *needs == want),
            "incompatible {bits:#x}: wanted {want:?}, got {:?}",
            got.map(|_| "a file system").map_err(|e| e.to_string())
        );
    }
    // The bit that says a file system may keep small files in their
    // inodes is no longer a reason to refuse it: it is read.
    let incompat = 0x2u32 | 0x40 | 0x8000;
    assert!(changed(96, &incompat.to_le_bytes()).is_ok());

    // Blocks counted in clusters, which is kept where a reader that only
    // reads is told it may read what it does not know — and may not.
    let got = changed(100, &0x201u32.to_le_bytes());
    assert!(matches!(got, Err(Error::Needs(Unsupported::BigAlloc))));
}

/// A tree of extents that cannot be walked, and a block number past the end
/// of the file system: both would otherwise be read as whatever lies there.
#[test]
fn a_map_that_leads_nowhere_is_told() {
    let (image, _) = by_hand(256, true);
    let fs = Ext::open(&image).unwrap();
    let node = fs.lookup_path("big.bin").unwrap().unwrap();
    let at = (5 * BLOCK + (node.ino - 1) * 256) as usize;

    // The signature of the extent tree in the inode, taken away.
    let mut broken = image.clone();
    broken[at + 40..at + 42].copy_from_slice(&0u16.to_le_bytes());
    let fs = Ext::open(&broken).unwrap();
    let node = fs.lookup_path("big.bin").unwrap().unwrap();
    let mut data = Vec::new();
    assert!(fs.file(&node).unwrap().read_to_end(&mut data).is_err());

    // An extent that says more entries than the inode has room for.
    let mut broken = image.clone();
    broken[at + 42..at + 44].copy_from_slice(&99u16.to_le_bytes());
    let fs = Ext::open(&broken).unwrap();
    let node = fs.lookup_path("big.bin").unwrap().unwrap();
    let mut data = Vec::new();
    assert!(fs.file(&node).unwrap().read_to_end(&mut data).is_err());

    // An extent pointing past the end of the file system.
    let mut broken = image.clone();
    broken[at + 40 + 12 + 8..at + 40 + 12 + 12].copy_from_slice(&BLOCKS.to_le_bytes());
    let fs = Ext::open(&broken).unwrap();
    let node = fs.lookup_path("big.bin").unwrap().unwrap();
    let mut data = Vec::new();
    let read = fs.file(&node).unwrap().read_to_end(&mut data);
    assert!(read.is_err(), "a block that is not on the file system");
}
