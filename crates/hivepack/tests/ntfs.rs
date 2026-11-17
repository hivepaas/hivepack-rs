//! NTFS file systems: a tree put into one by `mkntfs` and `ntfs-3g` and
//! read back out of it, against the bytes that went in.
//!
//! The library that reads the structures is a dependency and not a port,
//! so these tests are about the two things that makes true: that what it
//! reads comes back byte for byte, and that what it does *not* read is
//! refused rather than answered wrongly. The compressed file is the one
//! that matters most — the library hands back the compressed bytes with no
//! error at all, which `docs/ntfs.md` measures.
//!
//! See crates/hivepack/src/ntfs/ and docs/ntfs.md.

#![cfg(all(feature = "ntfs", feature = "image"))]
#![allow(clippy::unwrap_used)]

use std::collections::BTreeMap;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;

use hivepack::ntfs::{Entry, Error, Ntfs};

/// A folder in the system's temporary one, removed when dropped.
struct Scratch(PathBuf);

impl Scratch {
    fn new(what: &str) -> Scratch {
        let path = std::env::temp_dir().join(format!(
            "hivepack-ntfs-{}-{}",
            std::process::id(),
            what.replace([' ', '/', ','], "-")
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
        .find(|at| at.exists())?;
    Command::new(&path).arg("--version").output().ok()?;
    Some(path)
}

/// Runs a tool, and what it said if it failed.
fn said(at: &Path, args: &[&str]) -> (bool, String) {
    match Command::new(at).args(args).output() {
        Ok(out) => (
            out.status.success(),
            String::from_utf8_lossy(&out.stderr).to_string()
                + &String::from_utf8_lossy(&out.stdout),
        ),
        Err(e) => (false, e.to_string()),
    }
}

/// The bytes `big.bin` holds: a pattern, so that a run read in the wrong
/// order is told from one read in the right one.
fn pattern(len: usize) -> Vec<u8> {
    (0..len).map(|i| ((i * 7 + i / 251) % 256) as u8).collect()
}

/// What `comp/squashy.txt` holds: a line over and over, which is what
/// NTFS's own compression squashes hardest.
fn squashy() -> Vec<u8> {
    "the same line over and over, which LZNT1 should squash hard. "
        .repeat(20_000)
        .into_bytes()
}

/// What `sparse.bin` holds: a megabyte that was never written, and three
/// bytes that were.
fn sparse() -> Vec<u8> {
    let mut bytes = vec![0u8; 1 << 20];
    bytes.extend_from_slice(b"end");
    bytes
}

/// How many names `many/` holds: enough that the directory's index does
/// not fit in the record and NTFS has to put it out in its own clusters,
/// which is another path through the library.
const MANY: usize = 400;

/// An image, and what went into it.
struct Built {
    image: Vec<u8>,
    /// Every file, and the bytes it holds.
    files: BTreeMap<String, Vec<u8>>,
}

/// The image the tests read, built once, or why it could not be built.
fn built() -> Result<&'static Built, &'static str> {
    static ONCE: OnceLock<Result<Built, String>> = OnceLock::new();
    ONCE.get_or_init(build).as_ref().map_err(String::as_str)
}

/// Builds the image: `mkntfs` makes the file system, `ntfs-3g` mounts it so
/// that files can be written into it, and `python3` sets the two things
/// that are extended attributes rather than files — the flag that makes
/// NTFS compress what is written in a directory, and a stream beside a
/// file. Each is asked for on its own, and what is missing is said.
fn build() -> Result<Built, String> {
    let (Some(mkntfs), Some(ntfs3g), Some(fusermount), Some(python)) = (
        tool("mkntfs"),
        tool("ntfs-3g"),
        tool("fusermount"),
        tool("python3"),
    ) else {
        return Err("mkntfs, ntfs-3g, fusermount and python3 are not all installed".into());
    };
    let scratch = Scratch::new("built");
    let image = scratch.0.join("ntfs.img");
    let mount = scratch.0.join("mnt");
    std::fs::create_dir_all(&mount).unwrap();
    std::fs::write(&image, vec![0u8; 48 << 20]).unwrap();
    let at = image.to_str().unwrap();
    let (ok, told) = said(&mkntfs, &["-F", "-q", "-L", "probe", at]);
    if !ok {
        return Err(format!("this mkntfs could not make a file system: {told}"));
    }
    // The streams beside a file are extended attributes under this option,
    // which is how one gets written without Windows.
    let (ok, told) = said(
        &ntfs3g,
        &["-o", "streams_interface=xattr", at, mount.to_str().unwrap()],
    );
    if !ok {
        return Err(format!("this ntfs-3g could not mount the image: {told}"));
    }

    let mut files = BTreeMap::new();
    let result = fill(&mount, &python, &mut files);

    // Unmounted whether filling worked or not, as a mount left behind
    // would leave the image half written and the folder undeletable.
    let (ok, told) = said(&fusermount, &["-u", mount.to_str().unwrap()]);
    result?;
    if !ok {
        return Err(format!("the image could not be unmounted: {told}"));
    }
    Ok(Built {
        image: std::fs::read(&image).unwrap(),
        files,
    })
}

/// Writes everything the tests look for into the mounted file system.
fn fill(mount: &Path, python: &Path, files: &mut BTreeMap<String, Vec<u8>>) -> Result<(), String> {
    let mut put = |path: &str, bytes: Vec<u8>| {
        let at = mount.join(path);
        if let Some(dir) = at.parent() {
            std::fs::create_dir_all(dir).unwrap();
        }
        std::fs::write(&at, &bytes).unwrap();
        files.insert(path.to_string(), bytes);
    };

    // Short enough to sit in the file's own record.
    put("plain.txt", b"hello resident\n".to_vec());
    // Long enough to be out in the clusters.
    put("big.bin", pattern(1 << 20));
    put("dir/sub/deep.txt", b"deep\n".to_vec());
    // A name that is not ASCII, which NTFS keeps as UTF-16.
    put("tên-việt.txt", b"ten viet\n".to_vec());
    put("ads.txt", b"main data\n".to_vec());
    for i in 0..MANY {
        put(
            &format!("many/file-{i:04}.txt"),
            format!("entry {i}\n").into_bytes(),
        );
    }

    // A file with a hole in it: a megabyte seeked over and never written.
    let at = mount.join("sparse.bin");
    let mut file = std::fs::File::create(&at).unwrap();
    file.seek(SeekFrom::Start(1 << 20)).unwrap();
    file.write_all(b"end").unwrap();
    file.sync_all().unwrap();
    drop(file);
    files.insert("sparse.bin".into(), sparse());

    // A second name for a file that is already there.
    std::fs::hard_link(mount.join("plain.txt"), mount.join("hardlink.txt")).unwrap();
    files.insert("hardlink.txt".into(), files["plain.txt"].clone());

    // A file in many pieces: written a little at a time, with other files
    // growing in between so that what it takes is never next to itself.
    std::fs::create_dir_all(mount.join("frag")).unwrap();
    let mut target = std::fs::File::create(mount.join("frag/target.bin")).unwrap();
    let mut fillers: Vec<std::fs::File> = (0..3)
        .map(|i| std::fs::File::create(mount.join(format!("frag/filler-{i}.bin"))).unwrap())
        .collect();
    let mut bytes = Vec::new();
    for round in 0..100u8 {
        let piece = vec![round; 4096];
        target.write_all(&piece).unwrap();
        target.sync_all().unwrap();
        bytes.extend_from_slice(&piece);
        for filler in &mut fillers {
            filler.write_all(&[b'x'; 4096]).unwrap();
            filler.sync_all().unwrap();
        }
    }
    drop(target);
    for (i, filler) in fillers.into_iter().enumerate() {
        drop(filler);
        files.insert(format!("frag/filler-{i}.bin"), vec![b'x'; 100 * 4096]);
    }
    files.insert("frag/target.bin".into(), bytes);

    // The compressed file, and the stream beside `ads.txt`. Both are
    // extended attributes: `system.ntfs_attrib_be` is four bytes, big
    // endian, and 0x800 is the flag that makes NTFS compress what is
    // written in that directory from then on.
    std::fs::create_dir_all(mount.join("comp")).unwrap();
    // Python's own, rather than a script with paths written into it:
    // the paths go in as arguments, so nothing here has to be quoted.
    let script = r#"
import os, sys
comp, squashy, ads, stream = sys.argv[1:5]
os.setxattr(comp, b'system.ntfs_attrib_be', bytes([0, 0, 8, 0]))
with open(squashy + '.src', 'rb') as src, open(squashy, 'wb') as out:
    out.write(src.read())
want = bytes.fromhex(stream)
os.setxattr(ads, b'user.extra', want)
got = os.getxattr(ads, b'user.extra')
if got != want:
    sys.exit('the stream read back as %r' % (got,))
"#;
    // The bytes to compress go in beside the file rather than through the
    // script, so that what is compared with is this test's own. They are
    // written before the flag is set, so the source is not compressed and
    // the file written from it is.
    std::fs::write(mount.join("comp/squashy.txt.src"), squashy()).unwrap();
    let hex: String = STREAM.iter().map(|b| format!("{b:02x}")).collect();
    let (ok, told) = said(
        python,
        &[
            "-I",
            "-c",
            script,
            mount.join("comp").to_str().unwrap(),
            mount.join("comp/squashy.txt").to_str().unwrap(),
            mount.join("ads.txt").to_str().unwrap(),
            &hex,
        ],
    );
    std::fs::remove_file(mount.join("comp/squashy.txt.src")).unwrap();
    if !ok {
        return Err(format!(
            "this ntfs-3g has no extended attributes, so nothing could be compressed: {told}"
        ));
    }
    files.insert("comp/squashy.txt".into(), squashy());
    Ok(())
}

/// What the stream beside `ads.txt` holds.
const STREAM: &[u8] = b"this is the alternate stream";

/// The file system the tests read, or a printed reason and no test.
macro_rules! image {
    () => {
        match built() {
            Ok(built) => built,
            Err(why) => {
                eprintln!("no NTFS image to read: {why}");
                return;
            }
        }
    };
}

/// Every path in the image, and the entry at it.
fn walked<D: hivepack::image::Disk>(fs: &Ntfs<D>) -> BTreeMap<String, Entry> {
    let mut all = BTreeMap::new();
    let mut walk = fs.walk().unwrap();
    while let Some((path, entry)) = walk.next(fs).unwrap() {
        assert!(all.insert(path.clone(), entry).is_none(), "{path} twice");
    }
    all
}

#[test]
fn a_tree_reads_back_as_it_went_in() {
    let built = image!();
    let fs = Ntfs::open(built.image.as_slice()).unwrap();
    assert_eq!(fs.label(), Some("probe"));
    let all = walked(&fs);
    for (path, want) in &built.files {
        let entry = all
            .get(path)
            .unwrap_or_else(|| panic!("{path} is not in the image"));
        assert!(entry.is_file(), "{path} reads as a directory");
        assert_eq!(entry.size, want.len() as u64, "{path} is another length");
        // The compressed one is refused, which its own test is about.
        if entry.compressed {
            continue;
        }
        let mut got = Vec::new();
        fs.file(entry).unwrap().read_to_end(&mut got).unwrap();
        assert_eq!(got.len(), want.len(), "{path} reads another length");
        assert!(got == *want, "{path} reads other bytes");
    }
    // Nothing invented: every file the walk found is one that was written,
    // and the directories on the way to them.
    let dirs = ["dir", "dir/sub", "many", "comp", "frag"];
    for (path, entry) in &all {
        assert!(
            built.files.contains_key(path) || dirs.contains(&path.as_str()),
            "{path} is in the image and was never written ({entry:?})"
        );
    }
}

#[test]
fn a_compressed_file_is_refused_rather_than_read_wrongly() {
    let built = image!();
    let fs = Ntfs::open(built.image.as_slice()).unwrap();
    let entry = fs.lookup_path("comp/squashy.txt").unwrap().unwrap();
    // The premise: NTFS really did compress it. Without this the test
    // could pass on an image where there was nothing to refuse.
    assert!(
        entry.compressed,
        "nothing was compressed, so there is nothing to refuse"
    );
    assert_eq!(entry.size, squashy().len() as u64);
    // The library would hand back the compressed bytes here, with no error
    // at all: docs/ntfs.md has that measurement. Refusing is the whole
    // point of this module.
    assert!(matches!(fs.file(&entry), Err(Error::Compressed)));
    assert!(matches!(entry.readable(), Err(Error::Compressed)));
}

#[test]
fn the_stream_beside_a_file_is_not_the_file() {
    let built = image!();
    let fs = Ntfs::open(built.image.as_slice()).unwrap();
    let entry = fs.lookup_path("ads.txt").unwrap().unwrap();
    assert_eq!(entry.size, b"main data\n".len() as u64);
    let mut got = Vec::new();
    fs.file(&entry).unwrap().read_to_end(&mut got).unwrap();
    // The file's own data, and not the stream that is also in its record.
    assert_eq!(got, b"main data\n");
    assert_ne!(got, STREAM);
    // And the stream is not a file of its own in the directory.
    assert!(fs.lookup_path("ads.txt:extra").unwrap().is_none());
}

#[test]
fn a_hole_reads_as_the_zeroes_it_stands_for() {
    let built = image!();
    let fs = Ntfs::open(built.image.as_slice()).unwrap();
    let entry = fs.lookup_path("sparse.bin").unwrap().unwrap();
    assert!(entry.sparse, "the file system did not keep it sparsely");
    let mut got = Vec::new();
    fs.file(&entry).unwrap().read_to_end(&mut got).unwrap();
    assert_eq!(got, sparse());
}

#[test]
fn two_names_of_one_file_are_one_record() {
    let built = image!();
    let fs = Ntfs::open(built.image.as_slice()).unwrap();
    let one = fs.lookup_path("plain.txt").unwrap().unwrap();
    let other = fs.lookup_path("hardlink.txt").unwrap().unwrap();
    assert_eq!(one.record(), other.record());
    assert_eq!(one.links, 2);
    assert_eq!(other.links, 2);
    let mut got = Vec::new();
    fs.file(&other).unwrap().read_to_end(&mut got).unwrap();
    assert_eq!(got, b"hello resident\n");
}

#[test]
fn a_directory_too_long_for_its_record_reads_all_of_it() {
    let built = image!();
    let fs = Ntfs::open(built.image.as_slice()).unwrap();
    let many = fs.lookup_path("many").unwrap().unwrap();
    assert!(many.is_dir());
    let entries = fs.read_dir(&many).unwrap();
    assert_eq!(entries.len(), MANY);
    for i in 0..MANY {
        let name = format!("file-{i:04}.txt");
        let entry = entries.iter().find(|entry| entry.name == name);
        assert!(entry.is_some(), "{name} is not in the directory");
    }
}

#[test]
fn a_file_in_many_pieces_reads_in_order() {
    let built = image!();
    let fs = Ntfs::open(built.image.as_slice()).unwrap();
    let entry = fs.lookup_path("frag/target.bin").unwrap().unwrap();
    let want = &built.files["frag/target.bin"];
    // Read in pieces that do not line up with the runs, as a reader that
    // is right only when asked for whole runs would pass otherwise.
    let mut file = fs.file(&entry).unwrap();
    let mut got = Vec::new();
    let mut buf = [0u8; 777];
    loop {
        let read = file.read(&mut buf).unwrap();
        if read == 0 {
            break;
        }
        got.extend_from_slice(&buf[..read]);
    }
    assert_eq!(got.len(), want.len());
    assert!(got == *want);
    // And seeking lands where it says: the last byte, by itself.
    let mut file = fs.file(&entry).unwrap();
    file.seek(SeekFrom::End(-1)).unwrap();
    let mut last = [0u8; 1];
    file.read_exact(&mut last).unwrap();
    assert_eq!(last[0], *want.last().unwrap());
}

#[test]
fn what_is_not_ntfs_is_not_opened() {
    // No tools needed for this one, so it runs everywhere.
    //
    // The library checks the two bytes at the end of the boot sector and
    // never the name at its start, so each of these reaches it and is
    // turned away by whichever field it reads next happens not to hold.
    // hivepack checks the name, where "not NTFS" is the answer.
    let mut like_fat = vec![0u8; 1 << 20];
    like_fat[0..3].copy_from_slice(&[0xEB, 0x3C, 0x90]);
    like_fat[3..11].copy_from_slice(b"MSDOS5.0");
    like_fat[11..13].copy_from_slice(&512u16.to_le_bytes());
    like_fat[13] = 8;
    like_fat[510..512].copy_from_slice(&[0x55, 0xAA]);
    for (what, bytes) in [
        ("a FAT boot sector", like_fat),
        ("nothing at all", vec![0u8; 1 << 20]),
        ("a disk shorter than a name", vec![0u8; 4]),
    ] {
        assert!(
            matches!(Ntfs::open(bytes.as_slice()), Err(Error::Unrecognized)),
            "{what} opened as NTFS"
        );
    }
}

#[test]
fn a_disk_too_short_for_a_boot_sector_is_not_opened() {
    // No tools needed for this one either.
    //
    // The library panics rather than failing when the stream ends inside
    // the boot sector: `ntfs-0.4.0/src/error.rs:236`, where
    // `From<binrw::error::Error>` ends in `unreachable!()` under a comment
    // saying no attribute it uses can give another kind of error. binrw
    // wraps an `Io` error from a derived struct in `Error::Backtrace`, so
    // the `if let Error::Io` misses and the `unreachable!` fires. Measured
    // at each of these lengths; 512 and above are refused properly.
    //
    // So hivepack has to know the whole boot sector is there before it
    // hands the disk over. A short disk is not exotic — a partition whose
    // size field is wrong is one.
    for len in [11usize, 100, 256, 460, 511] {
        let mut bytes = vec![0u8; len];
        bytes[0..3].copy_from_slice(&[0xEB, 0x52, 0x90]);
        bytes[3..11].copy_from_slice(b"NTFS    ");
        assert!(
            matches!(Ntfs::open(bytes.as_slice()), Err(Error::Unrecognized)),
            "a disk of {len} bytes was not refused"
        );
    }
}
