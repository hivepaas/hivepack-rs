//! An NTFS file system built by `mkntfs` and `ntfs-3g`, for the tests that
//! read one and the tests that extract one.
//!
//! Building it takes four tools and a FUSE mount the system has to allow,
//! so it is built once and what could not be built is said rather than
//! asserted — except where `HIVEPACK_NTFS_REQUIRED` holds a value, which
//! is how CI holds the one job that installs the tools to having them.

#![allow(dead_code, clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeMap;
use std::io::{Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;

/// A folder in the system's temporary one, removed when dropped.
pub struct Scratch(PathBuf);

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
pub fn tool(name: &str) -> Option<PathBuf> {
    let path = ["/usr/sbin", "/usr/bin", "/sbin", "/bin", "/usr/local/sbin"]
        .into_iter()
        .map(|at| PathBuf::from(at).join(name))
        .find(|at| at.exists())?;
    Command::new(&path).arg("--version").output().ok()?;
    Some(path)
}

/// Runs a tool, and what it said if it failed.
pub fn said(at: &Path, args: &[&str]) -> (bool, String) {
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
pub fn pattern(len: usize) -> Vec<u8> {
    (0..len).map(|i| ((i * 7 + i / 251) % 256) as u8).collect()
}

/// What `comp/squashy.txt` holds: a line over and over, which is what
/// NTFS's own compression squashes hardest.
pub fn squashy() -> Vec<u8> {
    "the same line over and over, which LZNT1 should squash hard. "
        .repeat(20_000)
        .into_bytes()
}

/// What `sparse.bin` holds: a megabyte that was never written, and three
/// bytes that were.
pub fn sparse() -> Vec<u8> {
    let mut bytes = vec![0u8; 1 << 20];
    bytes.extend_from_slice(b"end");
    bytes
}

/// How many names `many/` holds: enough that the directory's index does
/// not fit in the record and NTFS has to put it out in its own clusters,
/// which is another path through the library.
pub const MANY: usize = 400;

/// An image, and what went into it.
pub struct Built {
    pub image: Vec<u8>,
    /// Every file, and the bytes it holds.
    pub files: BTreeMap<String, Vec<u8>>,
}

/// The image the tests read, built once, or why it could not be built.
///
/// Where `HIVEPACK_NTFS_REQUIRED` holds a value, not being able to build
/// it is a failure rather than a reason: CI gives it one on the job whose
/// tools it installs and that can mount what they write, as the data sets
/// do with `HIVEPACK_TESTDATA_REQUIRED`. Without that, a test that found
/// no tools and a test that read an image both pass, and `cargo test`
/// hides the printed reason for a test that passes, so the suite could say
/// nothing and look exactly the same.
///
/// **An empty value is not a value.** A workflow that sets the variable
/// for every system and fills it in for one leaves the others holding an
/// empty string, which is still set as far as the environment goes; the
/// first version of this read it with `var_os` and failed on macOS and
/// Windows for having been given nothing.
pub fn built() -> Result<&'static Built, &'static str> {
    static ONCE: OnceLock<Result<Built, String>> = OnceLock::new();
    let built = ONCE.get_or_init(build).as_ref().map_err(String::as_str);
    if let Err(why) = built {
        let required = std::env::var("HIVEPACK_NTFS_REQUIRED").unwrap_or_default();
        assert!(
            required.is_empty(),
            "HIVEPACK_NTFS_REQUIRED is set, so an image was to be built: {why}"
        );
    }
    built
}

/// Builds the image: `mkntfs` makes the file system, `ntfs-3g` mounts it so
/// that files can be written into it, and `python3` sets the two things
/// that are extended attributes rather than files — the flag that makes
/// NTFS compress what is written in a directory, and a stream beside a
/// file. Each is asked for on its own, and what is missing is said.
fn build() -> Result<Built, String> {
    // `fusermount3` on a system with FUSE 3 and `fusermount` on one with
    // FUSE 2; ntfs-3g takes either, and which it is says nothing about
    // whether an image can be built.
    let (Some(mkntfs), Some(ntfs3g), Some(fusermount), Some(python)) = (
        tool("mkntfs"),
        tool("ntfs-3g"),
        tool("fusermount3").or_else(|| tool("fusermount")),
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
pub const STREAM: &[u8] = b"this is the alternate stream";

/// The file system the tests read, or a printed reason and none: a test
/// that has no image says so and passes, unless `HIVEPACK_NTFS_REQUIRED`
/// holds a value, where [`built`] fails instead.
pub fn image_or_say() -> Option<&'static Built> {
    match built() {
        Ok(built) => Some(built),
        Err(why) => {
            eprintln!("no NTFS image to read: {why}");
            None
        }
    }
}
