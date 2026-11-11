//! What the SquashFS tests share: the oracle program, built with
//! squashfuse by `scripts/testdata.py`, the port's side of its answers, the
//! images, and how they are damaged.

// Test helpers: a broken oracle should stop the test.
#![allow(dead_code, clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::fmt::Write as _;
use std::io::{BufRead, BufReader, Read, Seek, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

use hivepack::squashfs::{Error, Inode, InodeId, MAX_DEPTH, Squashfs, Step};

pub fn repository() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

pub fn cache() -> PathBuf {
    std::env::var_os("HIVEPACK_TESTDATA")
        .map(PathBuf::from)
        .unwrap_or_else(|| repository().join("target/testdata"))
}

/// The set `name` of the cache, or `None` with a note when it is not
/// there; CI lists its group in `HIVEPACK_TESTDATA_REQUIRED`, and then a
/// missing set fails the test.
pub fn set(name: &str, group: &str) -> Option<PathBuf> {
    let folder = cache().join(name);
    if folder.join(".complete").exists() {
        return Some(folder);
    }
    let required = std::env::var("HIVEPACK_TESTDATA_REQUIRED").unwrap_or_default();
    assert!(
        !required.split(',').any(|g| g == "all" || g == group),
        "{name} is missing: run `python3 scripts/testdata.py fetch --group {group}`"
    );
    eprintln!("skipping: {name} is not there (scripts/testdata.py fetch --group {group})");
    None
}

/// The oracle program, running.
pub struct Oracle {
    child: Child,
    input: ChildStdin,
    output: BufReader<ChildStdout>,
}

impl Oracle {
    /// `tools/squashfs-oracle`, or `None` with a note when it has not been
    /// built.
    pub fn spawn() -> Option<Oracle> {
        let folder = set("squashfs-oracle", "generated")?;
        let mut child = Command::new(folder.join("oracle"))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .expect("the oracle starts");
        let input = child.stdin.take().expect("stdin");
        let output = BufReader::new(child.stdout.take().expect("stdout"));
        Some(Oracle {
            child,
            input,
            output,
        })
    }

    /// The lines of the answer to `request`, to the one that starts with
    /// `end`.
    pub fn ask(&mut self, request: &str) -> Vec<String> {
        writeln!(self.input, "{request}").expect("request sent");
        self.input.flush().expect("request sent");
        let mut lines = Vec::new();
        loop {
            let mut line = String::new();
            let n = self.output.read_line(&mut line).expect("answer read");
            assert!(n > 0, "the oracle stopped at {request:.200}");
            let line = line.trim_end().to_string();
            let end = line.starts_with("end");
            assert!(
                line != "end bad",
                "the oracle answered bad to {request:.200}"
            );
            lines.push(line);
            if end {
                return lines;
            }
        }
    }

    /// What squashfuse reads of the image at `path`, from `offset`.
    pub fn list(&mut self, path: &Path, offset: u64, limits: Limits) -> Vec<String> {
        self.ask(&format!(
            "list {offset} {} {} {}",
            limits.entries,
            limits.data,
            path.display()
        ))
    }
}

impl Drop for Oracle {
    fn drop(&mut self) {
        let _ = self.input.write_all(b"quit\n");
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// How much of a walk is compared: the entries, and each file's data.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    pub entries: u64,
    pub data: u64,
}

pub const WHOLE: Limits = Limits {
    entries: 1 << 40,
    data: 1 << 62,
};

pub fn hex(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return "-".into();
    }
    let mut text = String::with_capacity(2 * bytes.len());
    for byte in bytes {
        let _ = write!(text, "{byte:02x}");
    }
    text
}

pub const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;

pub fn fnv1a(mut hash: u64, bytes: &[u8]) -> u64 {
    for &b in bytes {
        hash ^= u64::from(b);
        hash = hash.wrapping_mul(0x0100_0000_01b3);
    }
    hash
}

/// What squashfuse reads past its buffer where the port fails: an entry of
/// a table past the end of its metadata block.
pub const PAST: &str = "an entry past the end of its metadata block";

/// The `sqfs_err` number of an error, or `past` for [`PAST`], where
/// squashfuse reads what is in memory after the block and the answers part.
fn code(e: &Error) -> String {
    if e.what() == PAST {
        "past".into()
    } else {
        (e.code() as u32).to_string()
    }
}

/// The port's answer to what the oracle is asked by [`Oracle::list`]: the
/// same lines, from the same calls in the same order.
pub fn port_list<R: Read + Seek>(reader: R, offset: u64, limits: Limits) -> Vec<String> {
    let mut out = Vec::new();
    let mut fs = match Squashfs::open_at(reader, offset) {
        Ok(fs) => fs,
        Err(e) => {
            out.push(format!("end init {}", code(&e)));
            return out;
        }
    };
    let sb = *fs.superblock();
    out.push(format!(
        "super {} {} {} {} {} {} {} {} {} {} {} {}",
        sb.s_major,
        sb.s_minor,
        sb.compression,
        sb.block_size,
        sb.block_log,
        sb.flags,
        sb.inodes,
        sb.fragments,
        sb.no_ids,
        sb.mkfs_time,
        sb.bytes_used,
        sb.root_inode
    ));
    let root_id = fs.root_id();
    describe(&mut fs, root_id, limits.data, &mut out);

    let mut walk = match fs.root().and_then(|root| fs.traverse(&root)) {
        Ok(walk) => walk,
        Err(e) => {
            out.push(format!("end walk {}", code(&e)));
            return out;
        }
    };
    let mut entries = 0u64;
    loop {
        if entries == limits.entries {
            out.push("end many".into());
            break;
        }
        let (path, entry) = match walk.next(&mut fs) {
            Ok(None) => {
                out.push("end ok".into());
                break;
            }
            Ok(Some(Step::DirEnd)) => {
                out.push("up".into());
                continue;
            }
            Ok(Some(Step::Entry { path, entry })) => (path, entry),
            Err(e) if e.what() == "a tree too deep" => {
                out.push("end deep".into());
                break;
            }
            Err(e) => {
                out.push(format!("end walk {}", code(&e)));
                break;
            }
        };
        entries += 1;
        out.push(format!(
            "entry {} {} {} {}",
            hex(&path),
            entry.inode_type,
            entry.inode_number,
            entry.inode
        ));
        describe(&mut fs, entry.inode, limits.data, &mut out);
        if fs.export_ok() {
            match fs.export_inode(entry.inode_number) {
                Ok(id) => out.push(format!("export {id}")),
                Err(e) => out.push(format!("export err {}", code(&e))),
            }
        }
        // The path as a C string.
        let c_path = &path[..path.iter().position(|&c| c == 0).unwrap_or(path.len())];
        match fs.root().and_then(|root| fs.lookup_path(&root, c_path)) {
            Ok(Some((id, _))) => out.push(format!("path 1 {}", id.unwrap_or(0))),
            Ok(None) => out.push("path 0".into()),
            Err(e) => out.push(format!("path err {}", code(&e))),
        }
    }
    let _ = MAX_DEPTH;
    out
}

fn describe<R: Read + Seek>(
    fs: &mut Squashfs<R>,
    id: InodeId,
    max_data: u64,
    out: &mut Vec<String>,
) {
    let inode: Inode = match fs.inode(id) {
        Ok(inode) => inode,
        Err(e) => {
            out.push(format!("inode err {}", code(&e)));
            return;
        }
    };
    let b = inode.base;
    let mut line = format!(
        "inode {} {:o} {} {} {} {} {} {} {} {}",
        b.inode_type,
        b.mode,
        b.uid,
        b.guid,
        b.mtime,
        b.inode_number,
        inode.nlink as i32,
        inode.xattr,
        inode.next.block,
        inode.next.offset
    );
    if inode.is_file() {
        let (frag, off) = inode.fragment();
        let _ = write!(
            line,
            " {} {} {frag} {off}",
            inode.start_block(),
            inode.file_size()
        );
    } else if inode.is_dir() {
        let (start, offset, size, count, parent) = inode.dir_info();
        let _ = write!(line, " {start} {offset} {size} {count} {parent}");
    } else if inode.is_symlink() {
        let _ = write!(line, " {}", inode.symlink_size());
    } else if inode.is_device() {
        let (major, minor) = inode.device();
        let _ = write!(line, " {} {}", major as i32, minor as i32);
    }
    out.push(line);

    match fs.stat(&inode) {
        Ok(st) => out.push(format!(
            "stat {:o} {} {} {} {} {} {}",
            st.mode, st.uid, st.gid, st.mtime, st.size, st.blksize, st.blocks
        )),
        Err(e) => out.push(format!("stat err {}", code(&e))),
    }

    if inode.is_symlink() {
        match fs.read_link(&inode) {
            Ok(target) => out.push(format!("link {}", hex(&target))),
            Err(e) => out.push(format!("link err {}", code(&e))),
        }
    }

    match fs.xattrs(&inode) {
        Err(e) => out.push(format!("xattrs err {}", code(&e))),
        Ok(xattrs) => {
            out.push(format!("xattrs {}", xattrs.remaining()));
            for xattr in xattrs {
                match xattr {
                    Ok(x) => out.push(format!("xattr {} {}", hex(&x.name), hex(&x.value))),
                    Err(e) => {
                        out.push(format!("xattr err {}", code(&e)));
                        break;
                    }
                }
            }
        }
    }

    if inode.is_file() {
        let size = inode.file_size();
        let mut buf = vec![0u8; 65536];
        let mut hash = FNV_OFFSET;
        let mut at = 0u64;
        let mut how = "end".to_string();
        while at < size {
            if at >= max_data {
                how = "limit".into();
                break;
            }
            let want = (size - at).min(65536).min(max_data - at) as usize;
            match fs.read_at(&inode, at, &mut buf[..want]) {
                Ok(n) => {
                    hash = fnv1a(hash, &buf[..n]);
                    at += n as u64;
                }
                Err(e) => {
                    how = format!("err {}", code(&e));
                    break;
                }
            }
        }
        out.push(format!("data {at} {hash:016x} {how}"));
    }
}

/// xorshift64*, so that failures can be replayed.
pub struct Rng(pub u64);

impl Rng {
    pub fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    pub fn below(&mut self, n: u64) -> u64 {
        if n == 0 { 0 } else { self.next() % n }
    }
}

/// The parts of an image that starts at `offset` in `image`, by where its
/// superblock says its tables start: the superblock, the data, and each
/// table to the next, as ranges of `image`.
pub fn regions(image: &[u8], offset: usize) -> Vec<(&'static str, usize, usize)> {
    let sb = &image[offset..];
    if sb.len() < 96 {
        return vec![("all", 0, image.len())];
    }
    let at = |i: usize| u64::from_le_bytes(sb[i..i + 8].try_into().unwrap());
    let len = image.len() - offset;
    let mut starts: Vec<(&'static str, u64)> = vec![
        ("superblock", 0),
        ("data", 96),
        ("inode table", at(64)),
        ("directory table", at(72)),
        ("fragment table", at(80)),
        ("export table", at(88)),
        ("id table", at(48)),
        ("xattr table", at(56)),
    ];
    starts.retain(|&(_, s)| s < len as u64);
    starts.sort_by_key(|&(_, s)| s);
    starts.dedup_by_key(|&mut (_, s)| s);
    let mut out = Vec::new();
    for (i, &(name, start)) in starts.iter().enumerate() {
        let end = starts.get(i + 1).map_or(len as u64, |&(_, s)| s);
        if end > start {
            out.push((name, offset + start as usize, offset + end as usize));
        }
    }
    out
}

/// Damaged copies of `image`: `count` of them, each a few bits flipped in
/// one of its regions, or a byte set, taken in turn, or the image cut
/// short; with what was done.
pub fn damaged(image: &[u8], offset: usize, count: usize, seed: u64) -> Vec<(String, Vec<u8>)> {
    let regions = regions(image, offset);
    let mut rng = Rng(seed | 1);
    let mut out = Vec::new();
    // Cut short: at each region's start and in its middle, and a byte off.
    for &(name, start, end) in &regions {
        for cut in [start, start + (end - start) / 2] {
            if cut > offset && out.len() < count / 4 {
                out.push((format!("cut in {name} at {cut}"), image[..cut].to_vec()));
            }
        }
    }
    if image.len() > 1 {
        out.push(("cut a byte".into(), image[..image.len() - 1].to_vec()));
    }
    let mut turn = 0;
    while out.len() < count {
        let (name, start, end) = regions[turn % regions.len()];
        turn += 1;
        let mut copy = image.to_vec();
        let how = match rng.below(4) {
            0 => {
                let at = start + rng.below((end - start) as u64) as usize;
                let bit = rng.below(8);
                copy[at] ^= 1 << bit;
                format!("bit {bit} of {at} in {name}")
            }
            1 => {
                let mut what = String::new();
                for _ in 0..1 + rng.below(4) {
                    let at = start + rng.below((end - start) as u64) as usize;
                    let bit = rng.below(8);
                    copy[at] ^= 1 << bit;
                    let _ = write!(what, "bit {bit} of {at}, ");
                }
                format!("{what}in {name}")
            }
            2 => {
                let at = start + rng.below((end - start) as u64) as usize;
                copy[at] = 0xff;
                format!("0xff at {at} in {name}")
            }
            _ => {
                let at = start + rng.below((end - start) as u64) as usize;
                copy[at] = 0;
                format!("0 at {at} in {name}")
            }
        };
        out.push((how, copy));
    }
    out
}

/// Where a 64-bit little-endian ELF file ends, by its section headers: an
/// AppImage's SquashFS image starts there.
pub fn elf_end(file: &[u8]) -> usize {
    let shoff = u64::from_le_bytes(file[0x28..0x30].try_into().unwrap());
    let shentsize = u16::from_le_bytes(file[0x3a..0x3c].try_into().unwrap());
    let shnum = u16::from_le_bytes(file[0x3c..0x3e].try_into().unwrap());
    (shoff + u64::from(shentsize) * u64::from(shnum)) as usize
}

/// A file in the temporary folder, removed when dropped.
pub struct Scratch(pub PathBuf);

impl Scratch {
    pub fn new(name: &str) -> Scratch {
        let dir = std::env::temp_dir().join(format!("hivepack-squashfs-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        Scratch(dir.join(name))
    }

    pub fn write(&self, bytes: &[u8]) -> &Path {
        std::fs::write(&self.0, bytes).unwrap();
        &self.0
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}
