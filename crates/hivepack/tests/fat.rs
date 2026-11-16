//! FAT file systems: the tree that went into an image read back out of it,
//! against what `qemu-img`'s `vvfat` writes from a folder and what
//! `mkfs.fat` writes; and file systems built byte by byte, each of which
//! `fsck.fat` is run over, so that a test passing is not the reader
//! agreeing with its own mistake.
//!
//! See crates/hivepack/src/fat/ and docs/fat.md.

#![cfg(all(feature = "fat", feature = "image"))]
#![allow(clippy::unwrap_used)]

use std::collections::BTreeMap;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Command;

use hivepack::fat::{Entry, Error, Fat, Kind};
use hivepack::image::{Disk, Part, Table, partitions};

/// A folder in the system's temporary one, removed when dropped.
struct Scratch(PathBuf);

impl Scratch {
    fn new(what: &str) -> Scratch {
        let path = std::env::temp_dir().join(format!(
            "hivepack-fat-{}-{}",
            std::process::id(),
            what.replace(' ', "-")
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
    let path = ["/usr/bin", "/usr/sbin", "/bin", "/sbin", "/usr/local/bin"]
        .into_iter()
        .map(|at| PathBuf::from(at).join(name))
        .find(|p| p.exists())?;
    Command::new(&path).arg("--help").output().ok()?;
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

/// `fsck.fat` over an image, where it is installed: what says a file system
/// built by hand is one, rather than only one this reader likes.
fn sound(what: &str, image: &[u8]) {
    let Some(fsck) = tool("fsck.fat") else {
        eprintln!("fsck.fat cannot be run here: {what} is not checked by it");
        return;
    };
    let s = Scratch::new(&format!("fsck {what}"));
    let path = s.0.join("fs.img");
    std::fs::write(&path, image).unwrap();
    let out = Command::new(&fsck)
        .args(["-n", path.to_str().unwrap()])
        .output()
        .unwrap();
    let said = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        out.status.success(),
        "{what}: fsck.fat does not call this a FAT file system:\n{said}"
    );
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

/// A folder of files to put into an image: short names and long, a name of
/// more than ASCII, a file of several clusters, one of none, and a folder
/// inside a folder.
fn a_tree(at: &Path) -> BTreeMap<String, Option<Vec<u8>>> {
    let mut want: BTreeMap<String, Option<Vec<u8>>> = BTreeMap::new();
    let mut file = |path: &str, bytes: Vec<u8>| {
        let whole = at.join(path);
        std::fs::create_dir_all(whole.parent().unwrap()).unwrap();
        std::fs::write(&whole, &bytes).unwrap();
        want.insert(path.to_owned(), Some(bytes));
    };
    file("README.TXT", b"a short name, as MS-DOS had them\n".to_vec());
    file("lower.txt", b"a name in one case\n".to_vec());
    file("big.bin", pattern(70_000, 7));
    file("empty.dat", Vec::new());
    file("a long name with spaces.text", b"VFAT\n".to_vec());
    file(
        "ten dai.txt",
        b"more than ASCII goes in the long name\n".to_vec(),
    );
    file("sub/deep/inside.txt", b"two folders down\n".to_vec());
    want.insert("sub".to_owned(), None);
    want.insert("sub/deep".to_owned(), None);
    want
}

/// Everything the file system holds, by its path, with each file's bytes.
fn what_it_holds<D: Disk>(fat: &Fat<D>) -> BTreeMap<String, Option<Vec<u8>>> {
    let mut holds = BTreeMap::new();
    let mut walk = fat.walk().unwrap();
    while let Some((path, entry)) = walk.next(fat).unwrap() {
        let what = if entry.is_dir() {
            None
        } else {
            let mut data = Vec::new();
            // Read in pieces that do not line up with the clusters.
            let mut file = fat.file(&entry).unwrap();
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
                entry.size,
                "{path}: as many bytes as the record says"
            );
            Some(data)
        };
        assert!(holds.insert(path.clone(), what).is_none(), "{path}: twice");
    }
    holds
}

/// A folder through `vvfat`, which is QEMU's own way of making a FAT file
/// system out of one, and then read back.
///
/// Only `floppy:` and `16:` are used. `fat:32:` writes a FAT16 boot sector
/// and a root directory whose records name cluster 1, which no file system
/// has; `fsck.fat` finds long names of nothing in it. QEMU says as much
/// when it writes one ("FAT32 has not been tested"), so it is no oracle,
/// and FAT32 is checked by `mkfs.fat` and by hand instead.
fn through_vvfat(what: &str, subformat: &str, partitioned: bool) {
    let Some(qemu) = tool("qemu-img") else {
        eprintln!("qemu-img cannot be run here: {what} is not checked against it");
        return;
    };
    let s = Scratch::new(what);
    let from = s.0.join("tree");
    std::fs::create_dir_all(&from).unwrap();
    let want = a_tree(&from);
    let image = s.0.join("fs.img");
    run(
        &qemu,
        &[
            "convert",
            "-f",
            "vvfat",
            "-O",
            "raw",
            &format!("fat:{subformat}{}", from.to_str().unwrap()),
            image.to_str().unwrap(),
        ],
    );
    let file = std::fs::File::open(&image).unwrap();
    let holds = if partitioned {
        // What `vvfat` writes for a disk rather than a floppy is a disk:
        // a master boot record, and the file system in its one partition.
        let found = partitions(&file).unwrap().unwrap();
        assert_eq!(found.table, Table::Mbr, "{what}");
        let part = &found.partitions[0];
        let fat = Fat::open(Part::new(&file, part.at, part.size)).unwrap();
        assert_eq!(fat.kind(), Kind::Fat16, "{what}");
        what_it_holds(&fat)
    } else {
        let fat = Fat::open(&file).unwrap();
        assert_eq!(fat.kind(), Kind::Fat12, "{what}");
        what_it_holds(&fat)
    };
    assert_eq!(holds, want, "{what}: not the tree that went in");
}

#[test]
fn a_fat12_file_system_reads_as_the_tree_that_went_into_it() {
    through_vvfat("floppy", "floppy:", false);
}

#[test]
fn a_fat16_file_system_in_a_partition_reads_through_the_table() {
    through_vvfat("in a partition", "16:", true);
}

/// What `mkfs.fat` writes, which is the file system every Linux tool makes:
/// each of the three, with sector and cluster sizes of its own and a label.
/// There are no files in one it writes, so what is read is what the boot
/// sector says and the label a record of the root directory holds.
#[test]
fn what_mkfs_fat_writes_is_read_as_it_says() {
    let Some(mkfs) = tool("mkfs.fat") else {
        eprintln!("mkfs.fat cannot be run here: what it writes is not checked");
        return;
    };
    let s = Scratch::new("mkfs");
    // Enough room for each kind: FAT12 wants few clusters, FAT32 many.
    for (bits, kib, sector, per_cluster) in [
        (12, 2048, 512, 4),
        (12, 1440, 512, 1),
        (16, 65_536, 512, 4),
        (16, 65_536, 1024, 1),
        (32, 262_144, 512, 8),
        (32, 262_144, 4096, 1),
    ] {
        let what =
            format!("FAT{bits} of {kib} KiB, {sector}-byte sectors, {per_cluster} to a cluster");
        let path = s.0.join("fs.img");
        std::fs::write(&path, vec![0u8; kib * 1024]).unwrap();
        run(
            &mkfs,
            &[
                "-F",
                &bits.to_string(),
                "-S",
                &sector.to_string(),
                "-s",
                &per_cluster.to_string(),
                "-n",
                "HIVEPACK",
                path.to_str().unwrap(),
            ],
        );
        let file = std::fs::File::open(&path).unwrap();
        let fat = Fat::open(&file)
            .map_err(|e| format!("{what}: {e}"))
            .unwrap();
        assert_eq!(fat.kind().says(), format!("FAT{bits}"), "{what}");
        assert_eq!(fat.label(), Some("HIVEPACK"), "{what}");
        assert_eq!(fat.cluster_size(), sector * per_cluster, "{what}");
        assert!(fat.read_root().unwrap().is_empty(), "{what}: no files yet");
        assert!(fat.lookup_path("nothing.txt").unwrap().is_none(), "{what}");
    }
}

/// Microsoft's specification says how many clusters there are is what tells
/// the three apart, and for FAT32 that is wrong: `mkfs.fat -F 32` on 32 MiB
/// writes a file system of fewer clusters than the rule's own number for
/// FAT32, whose table is four bytes to an entry all the same. Reading it by
/// the rule reads the table two bytes at a time and answers a tree that was
/// never on it.
#[test]
fn a_fat32_of_fewer_clusters_than_the_rule_allows_is_still_a_fat32() {
    let Some(mkfs) = tool("mkfs.fat") else {
        eprintln!("mkfs.fat cannot be run here: the small FAT32 is not checked");
        return;
    };
    let s = Scratch::new("small fat32");
    let path = s.0.join("fs.img");
    std::fs::write(&path, vec![0u8; 32 << 20]).unwrap();
    run(
        &mkfs,
        &["-F", "32", "-s", "1", "-n", "SMALL", path.to_str().unwrap()],
    );
    let file = std::fs::File::open(&path).unwrap();
    let fat = Fat::open(&file).unwrap();
    assert_eq!(fat.kind(), Kind::Fat32);
    assert!(
        fat.clusters() < 65_525,
        "fewer clusters than the rule calls FAT32, and a FAT32 all the same"
    );
    assert_eq!(fat.label(), Some("SMALL"));
}

// --- File systems built byte by byte -------------------------------------

/// What a file system built here is made of. The numbers are the ones
/// `mkfs.fat` writes, so that `fsck.fat` has nothing to say about them.
struct Build {
    bits: u8,
    sector: u32,
    per_cluster: u32,
    clusters: u32,
    root_entries: u32,
    reserved: u32,
    label: [u8; 11],
    /// One entry for each cluster, the two the format keeps included.
    fat: Vec<u32>,
    /// The data area, as long as there are clusters.
    data: Vec<u8>,
    /// The records of the root directory.
    root: Vec<u8>,
    /// Which cluster the root directory is in, for FAT32.
    root_cluster: u32,
}

impl Build {
    /// A file system of `clusters` clusters of one sector each, which is
    /// what makes a chain easy to lay out by hand.
    ///
    /// Nothing in a boot sector says whether a file system is FAT12 or
    /// FAT16: how many clusters there are is what tells them apart, so a
    /// file system of 64 clusters is FAT12 however wide its table was
    /// written. Asking for one and building the other is what this
    /// refuses, having once built it.
    fn new(bits: u8, clusters: u32) -> Build {
        match bits {
            12 => assert!(clusters < 4085, "{clusters} clusters is not FAT12"),
            16 => assert!(
                (4085..65_525).contains(&clusters),
                "{clusters} clusters is not FAT16"
            ),
            _ => {}
        }
        let root_entries = if bits == 32 { 0 } else { 512 };
        let reserved = if bits == 32 { 32 } else { 1 };
        let mut build = Build {
            bits,
            sector: 512,
            per_cluster: 1,
            clusters,
            root_entries,
            reserved,
            label: *b"BY HAND    ",
            fat: vec![0; clusters as usize + 2],
            data: vec![0; (clusters * 512) as usize],
            root: Vec::new(),
            root_cluster: 2,
        };
        // The first two entries are not clusters: the first holds the media
        // byte with every other bit set, and the second says a chain ends.
        build.fat[0] = build.end() & !0xFF | 0xF8;
        build.fat[1] = build.end();
        build
    }

    /// What the table says is the end of a chain.
    fn end(&self) -> u32 {
        match self.bits {
            12 => 0x0FFF,
            16 => 0xFFFF,
            _ => 0x0FFF_FFFF,
        }
    }

    /// How many bytes a cluster is.
    fn cluster(&self) -> usize {
        (self.sector * self.per_cluster) as usize
    }

    /// Puts `bytes` in the clusters `at`, chained in the order they are
    /// given, and answers the first of them.
    fn put(&mut self, bytes: &[u8], at: &[u32]) -> u32 {
        let cluster = self.cluster();
        assert!(bytes.len() <= at.len() * cluster, "not enough clusters");
        for (i, which) in at.iter().enumerate() {
            let from = (*which as usize - 2) * cluster;
            let piece =
                &bytes[(i * cluster).min(bytes.len())..((i + 1) * cluster).min(bytes.len())];
            self.data[from..from + piece.len()].copy_from_slice(piece);
            self.fat[*which as usize] = at.get(i + 1).copied().unwrap_or(self.end());
        }
        at[0]
    }

    /// The whole image.
    fn image(&self) -> Vec<u8> {
        let sector = self.sector as usize;
        let fat_sectors = self.fat_sectors() as usize;
        let root_sectors = (self.root_entries as usize * 32).div_ceil(sector);
        let before = self.reserved as usize + 2 * fat_sectors + root_sectors;
        let mut image =
            vec![0u8; (before + self.clusters as usize * self.per_cluster as usize) * sector];
        image[..sector].copy_from_slice(&self.boot());
        if self.bits == 32 {
            // What FAT32 keeps beside the boot sector: the numbers a system
            // reads to know how much room is free, and a copy of the boot
            // sector six sectors in.
            let info = sector;
            image[info..info + 4].copy_from_slice(&0x4161_5252u32.to_le_bytes());
            image[info + 484..info + 488].copy_from_slice(&0x6141_7272u32.to_le_bytes());
            let free = self.fat[2..].iter().filter(|e| **e == 0).count() as u32;
            image[info + 488..info + 492].copy_from_slice(&free.to_le_bytes());
            image[info + 492..info + 496].copy_from_slice(&u32::MAX.to_le_bytes());
            image[info + 508..info + 512].copy_from_slice(&[0x00, 0x00, 0x55, 0xAA]);
            let backup = 6 * sector;
            image[backup..backup + sector].copy_from_slice(&self.boot());
        }
        let packed = self.packed();
        for copy in 0..2 {
            let at = (self.reserved as usize + copy * fat_sectors) * sector;
            image[at..at + packed.len()].copy_from_slice(&packed);
        }
        let root_at = (self.reserved as usize + 2 * fat_sectors) * sector;
        if self.bits != 32 {
            image[root_at..root_at + self.root.len()].copy_from_slice(&self.root);
        }
        let data_at = before * sector;
        image[data_at..data_at + self.data.len()].copy_from_slice(&self.data);
        image
    }

    /// How many sectors a copy of the table takes.
    fn fat_sectors(&self) -> u32 {
        let entries = self.clusters + 2;
        let bytes = match self.bits {
            12 => (entries * 3).div_ceil(2),
            16 => entries * 2,
            _ => entries * 4,
        };
        bytes.div_ceil(self.sector)
    }

    /// The table, as it lies in the file system.
    fn packed(&self) -> Vec<u8> {
        let mut raw = vec![0u8; (self.fat_sectors() * self.sector) as usize];
        for (i, value) in self.fat.iter().enumerate() {
            match self.bits {
                12 => {
                    // Twelve bits to an entry, so two share a byte.
                    let at = i + i / 2;
                    if i.is_multiple_of(2) {
                        raw[at] = (*value & 0xFF) as u8;
                        raw[at + 1] = (raw[at + 1] & 0xF0) | ((*value >> 8) & 0x0F) as u8;
                    } else {
                        raw[at] = (raw[at] & 0x0F) | (((*value & 0x0F) << 4) as u8);
                        raw[at + 1] = ((*value >> 4) & 0xFF) as u8;
                    }
                }
                16 => raw[i * 2..i * 2 + 2].copy_from_slice(&(*value as u16).to_le_bytes()),
                _ => raw[i * 4..i * 4 + 4].copy_from_slice(&value.to_le_bytes()),
            }
        }
        raw
    }

    /// The boot sector.
    fn boot(&self) -> Vec<u8> {
        let mut boot = vec![0u8; self.sector as usize];
        boot[..3].copy_from_slice(&[0xEB, 0x3C, 0x90]);
        boot[3..11].copy_from_slice(b"HIVEPACK");
        boot[11..13].copy_from_slice(&(self.sector as u16).to_le_bytes());
        boot[13] = self.per_cluster as u8;
        boot[14..16].copy_from_slice(&(self.reserved as u16).to_le_bytes());
        boot[16] = 2;
        boot[17..19].copy_from_slice(&(self.root_entries as u16).to_le_bytes());
        boot[21] = 0xF8;
        boot[24..26].copy_from_slice(&63u16.to_le_bytes());
        boot[26..28].copy_from_slice(&255u16.to_le_bytes());
        let root_sectors = (self.root_entries * 32).div_ceil(self.sector);
        let total = self.reserved
            + 2 * self.fat_sectors()
            + root_sectors
            + self.clusters * self.per_cluster;
        if self.bits == 32 {
            boot[32..36].copy_from_slice(&total.to_le_bytes());
            boot[36..40].copy_from_slice(&self.fat_sectors().to_le_bytes());
            boot[44..48].copy_from_slice(&self.root_cluster.to_le_bytes());
            boot[48..50].copy_from_slice(&1u16.to_le_bytes());
            boot[50..52].copy_from_slice(&6u16.to_le_bytes());
            boot[64] = 0x80;
            boot[66] = 0x29;
            boot[67..71].copy_from_slice(&0x1234_5678u32.to_le_bytes());
            boot[71..82].copy_from_slice(&self.label);
            boot[82..90].copy_from_slice(b"FAT32   ");
        } else {
            if total <= u32::from(u16::MAX) {
                boot[19..21].copy_from_slice(&(total as u16).to_le_bytes());
            } else {
                boot[32..36].copy_from_slice(&total.to_le_bytes());
            }
            boot[22..24].copy_from_slice(&(self.fat_sectors() as u16).to_le_bytes());
            boot[36] = 0x80;
            boot[38] = 0x29;
            boot[39..43].copy_from_slice(&0x1234_5678u32.to_le_bytes());
            boot[43..54].copy_from_slice(&self.label);
            boot[54..62].copy_from_slice(if self.bits == 12 {
                b"FAT12   "
            } else {
                b"FAT16   "
            });
        }
        let end = self.sector as usize;
        boot[end - 2..end].copy_from_slice(&[0x55, 0xAA]);
        boot
    }
}

/// One directory record.
fn record(name: &[u8; 11], attributes: u8, nt: u8, first: u32, size: u32) -> Vec<u8> {
    let mut raw = vec![0u8; 32];
    raw[..11].copy_from_slice(name);
    raw[11] = attributes;
    raw[12] = nt;
    // 2024-02-29 13:45:30, so that what is read can be compared with it.
    let date: u16 = ((2024 - 1980) << 9) | (2 << 5) | 29;
    let time: u16 = (13 << 11) | (45 << 5) | 15;
    raw[14..16].copy_from_slice(&time.to_le_bytes());
    raw[16..18].copy_from_slice(&date.to_le_bytes());
    raw[18..20].copy_from_slice(&date.to_le_bytes());
    raw[20..22].copy_from_slice(&((first >> 16) as u16).to_le_bytes());
    raw[22..24].copy_from_slice(&time.to_le_bytes());
    raw[24..26].copy_from_slice(&date.to_le_bytes());
    raw[26..28].copy_from_slice(&(first as u16).to_le_bytes());
    raw[28..32].copy_from_slice(&size.to_le_bytes());
    raw
}

/// The checksum of an 8.3 name, which every record of a long name carries.
fn checksum(short: &[u8; 11]) -> u8 {
    short.iter().fold(0u8, |sum, byte| {
        ((sum & 1) << 7).wrapping_add(sum >> 1).wrapping_add(*byte)
    })
}

/// The records of a long name, in the order a file system holds them: the
/// last piece first, each with the checksum of the 8.3 name it belongs to.
fn long(name: &str, sum: u8) -> Vec<u8> {
    let characters: Vec<u16> = name.encode_utf16().collect();
    let pieces: Vec<&[u16]> = characters.chunks(13).collect();
    let mut raw = Vec::new();
    for (i, piece) in pieces.iter().enumerate().rev() {
        let mut one = vec![0u8; 32];
        one[0] = (i as u8 + 1) | if i + 1 == pieces.len() { 0x40 } else { 0 };
        one[11] = 0x0F;
        one[13] = sum;
        let at = [1, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30];
        for (c, where_) in at.iter().enumerate() {
            let value = match piece.get(c) {
                Some(c) => *c,
                // What ends the name, and what pads what is left.
                None if c == piece.len() && i + 1 == pieces.len() => 0,
                None => 0xFFFF,
            };
            one[*where_..*where_ + 2].copy_from_slice(&value.to_le_bytes());
        }
        raw.extend_from_slice(&one);
    }
    raw
}

/// A file system with one of everything in it, built by hand.
fn by_hand(bits: u8) -> (Vec<u8>, BTreeMap<String, Option<Vec<u8>>>) {
    // Enough clusters to be the kind it says, which for FAT16 is more than
    // four thousand of them.
    let mut build = Build::new(bits, if bits == 16 { 4200 } else { 64 });
    // FAT32 keeps its root in a chain, which takes a cluster of its own.
    let first = if bits == 32 { 3 } else { 2 };
    let mut want: BTreeMap<String, Option<Vec<u8>>> = BTreeMap::new();

    let short = b"README  TXT";
    let text = b"a short name\n".to_vec();
    let at = build.put(&text, &[first]);
    let mut root = record(short, 0x20, 0, at, text.len() as u32);
    want.insert("README.TXT".to_owned(), Some(text));

    // A name in one case, which the byte Windows NT took says to show as it
    // was written.
    let lower = b"LOWER   TXT";
    let text = b"one case\n".to_vec();
    let at = build.put(&text, &[first + 1]);
    root.extend(record(lower, 0x20, 0x18, at, text.len() as u32));
    want.insert("lower.txt".to_owned(), Some(text));

    // A long name, over a chain whose clusters do not follow one another,
    // so that a read across them is a read of two places.
    let packed = b"ALONGN~1TXT";
    let name = "a long name of more than thirteen characters.txt";
    let text = pattern(1300, 3);
    let at = build.put(&text, &[first + 2, first + 7, first + 4]);
    root.extend(long(name, checksum(packed)));
    root.extend(record(packed, 0x20, 0, at, text.len() as u32));
    want.insert(name.to_owned(), Some(text));

    // A name of more than ASCII, which can only be a long one.
    let wide = b"TNDI~1  TXT";
    let name = "tên dài.txt";
    let text = b"more than ASCII\n".to_vec();
    let at = build.put(&text, &[first + 5]);
    root.extend(long(name, checksum(wide)));
    root.extend(record(wide, 0x20, 0, at, text.len() as u32));
    want.insert(name.to_owned(), Some(text));

    // A file of no bytes, which is given no cluster at all.
    root.extend(record(b"EMPTY   DAT", 0x20, 0, 0, 0));
    want.insert("EMPTY.DAT".to_owned(), Some(Vec::new()));

    // A record whose file was deleted, which is read over.
    let mut gone = record(b"GONE    TXT", 0x20, 0, first + 6, 5);
    gone[0] = 0xE5;
    root.extend(gone);

    // A folder, which holds the two records a file system needs to find its
    // way about and one file.
    let inside = b"INSIDE  TXT";
    let text = b"in a folder\n".to_vec();
    let at = build.put(&text, &[first + 6]);
    let mut records = record(b".          ", 0x10, 0, first + 3, 0);
    // The parent is the root directory, which `..` names as cluster 0 even
    // in FAT32, where the root is a chain like any other.
    records.extend(record(b"..         ", 0x10, 0, 0, 0));
    records.extend(record(inside, 0x20, 0, at, text.len() as u32));
    let folder = build.put(&records, &[first + 3]);
    root.extend(record(b"SUB        ", 0x10, 0, folder, 0));
    want.insert("SUB".to_owned(), None);
    want.insert("SUB/INSIDE.TXT".to_owned(), Some(text));

    // The label, which a tool keeps as a record of the root directory.
    let mut label = record(b"BY HAND    ", 0x08, 0, 0, 0);
    label[20..22].fill(0);
    let mut whole = label;
    whole.extend(root);
    if bits == 32 {
        build.put(&whole, &[build.root_cluster]);
    } else {
        build.root = whole;
    }
    (build.image(), want)
}

#[test]
fn a_file_system_built_by_hand_reads_as_it_was_built() {
    for bits in [12u8, 16, 32] {
        let what = format!("FAT{bits} by hand");
        let (image, want) = by_hand(bits);
        sound(&what, &image);
        let fat = Fat::open(&image)
            .map_err(|e| format!("{what}: {e}"))
            .unwrap();
        assert_eq!(fat.kind().says(), format!("FAT{bits}"), "{what}");
        assert_eq!(fat.label(), Some("BY HAND"), "{what}");
        assert_eq!(what_it_holds(&fat), want, "{what}");

        // The times every record was given, read back off one of them.
        let entry = fat.lookup_path("README.TXT").unwrap().unwrap();
        let at = entry.modified.unwrap();
        assert_eq!(
            (at.year, at.month, at.day, at.hour, at.minute, at.second),
            (2024, 2, 29, 13, 45, 30),
            "{what}"
        );
    }
}

/// Paths, looked up by either of a file's names and without regard to the
/// case of them, as every system that reads a FAT file system does.
#[test]
fn a_path_is_looked_up_by_either_name_and_in_any_case() {
    let (image, _) = by_hand(16);
    let fat = Fat::open(&image).unwrap();
    for path in [
        "README.TXT",
        "readme.txt",
        "/README.TXT",
        "./README.TXT",
        "\\README.TXT",
    ] {
        assert!(fat.lookup_path(path).unwrap().is_some(), "{path}");
    }
    // The long name, and the 8.3 name the file system holds beside it.
    assert!(
        fat.lookup_path("a long name of more than thirteen characters.txt")
            .unwrap()
            .is_some()
    );
    assert!(fat.lookup_path("alongn~1.txt").unwrap().is_some());
    assert!(fat.lookup_path("tên dài.txt").unwrap().is_some());
    assert_eq!(
        fat.lookup_path("sub/inside.txt").unwrap().unwrap().short,
        "INSIDE.TXT"
    );
    assert!(fat.lookup_path("sub/nothing.txt").unwrap().is_none());
    assert!(fat.lookup_path("nowhere/at/all").unwrap().is_none());
    // A file is not a folder: there is nothing inside it to go on to.
    assert!(fat.lookup_path("README.TXT/more").unwrap().is_none());
    // The root itself, which is no entry.
    assert!(fat.lookup_path("/").unwrap().is_none());
}

#[test]
fn a_folder_is_not_a_file_and_a_file_is_not_a_folder() {
    let (image, _) = by_hand(12);
    let fat = Fat::open(&image).unwrap();
    let folder = fat.lookup_path("SUB").unwrap().unwrap();
    let file = fat.lookup_path("README.TXT").unwrap().unwrap();
    assert!(matches!(fat.file(&folder), Err(Error::NotAFile)));
    assert!(matches!(fat.read_dir(&file), Err(Error::NotADirectory)));
}

/// A long name counts only where it was written for the file it lies in
/// front of, which the checksum of the 8.3 name says. One left behind by a
/// tool that wrote over the record after it is not the file's name.
#[test]
fn a_long_name_whose_checksum_is_not_the_files_is_not_its_name() {
    let mut build = Build::new(12, 32);
    let short = b"README  TXT";
    let text = b"short\n".to_vec();
    let at = build.put(&text, &[2]);
    // The name belongs to a file that is not there any more.
    build.root = long("a name of something else.txt", 0x11);
    build
        .root
        .extend(record(short, 0x20, 0, at, text.len() as u32));
    let image = build.image();
    let fat = Fat::open(&image).unwrap();
    let root = fat.read_root().unwrap();
    assert_eq!(root.len(), 1);
    assert_eq!(
        root[0].name, "README.TXT",
        "the 8.3 name, as the long one is not this file's"
    );
    assert_eq!(root[0].short, "README.TXT");
}

/// The bytes of an 8.3 name above ASCII, which are code page 437: what every
/// IBM PC had, and what Linux reads a FAT file system in unless it is told
/// otherwise.
#[test]
fn the_bytes_of_a_name_above_ascii_are_code_page_437() {
    let mut build = Build::new(12, 16);
    let text = b"old\n".to_vec();
    let at = build.put(&text, &[2]);
    build.root = record(b"\x82\x84\x94     TXT", 0x20, 0, at, text.len() as u32);
    let image = build.image();
    let fat = Fat::open(&image).unwrap();
    let root = fat.read_root().unwrap();
    assert_eq!(root[0].short, "éäö.TXT");
}

#[test]
fn a_chain_that_leads_back_into_itself_is_told() {
    let mut build = Build::new(12, 32);
    let text = pattern(2000, 1);
    build.put(&text, &[2, 3, 4, 5]);
    // The last cluster of the chain points at the first of it.
    build.fat[5] = 2;
    build.root = record(b"LOOP    BIN", 0x20, 0, 2, text.len() as u32);
    let image = build.image();
    let fat = Fat::open(&image).unwrap();
    let entry = fat.lookup_path("LOOP.BIN").unwrap().unwrap();
    assert!(matches!(fat.file(&entry), Err(Error::Chain { .. })));
}

#[test]
fn a_cluster_the_table_marks_as_not_to_be_used_is_told() {
    let mut build = Build::new(16, 4200);
    let text = pattern(1000, 2);
    build.put(&text, &[2, 3]);
    build.fat[3] = 0xFFF7;
    build.root = record(b"BAD     BIN", 0x20, 0, 2, text.len() as u32);
    let image = build.image();
    let fat = Fat::open(&image).unwrap();
    let entry = fat.lookup_path("BAD.BIN").unwrap().unwrap();
    assert!(matches!(fat.file(&entry), Err(Error::Chain { at: 3 })));
}

/// A record naming cluster 1, which no file system has: the data begins at
/// cluster 2, and the two before it are the table's own. This is what
/// QEMU's `vvfat` writes in its FAT32 mode, which is why that is no oracle.
#[test]
fn a_record_naming_a_cluster_the_file_system_has_not_got_is_told() {
    let mut build = Build::new(12, 32);
    build.root = record(b"WRONG   BIN", 0x20, 0, 1, 512);
    let image = build.image();
    let fat = Fat::open(&image).unwrap();
    let entry = fat.lookup_path("WRONG.BIN").unwrap().unwrap();
    assert!(matches!(fat.file(&entry), Err(Error::Chain { at: 1 })));
}

/// A folder whose records lead back to a folder above it, which walking
/// would otherwise go round for ever.
#[test]
fn a_folder_that_leads_back_into_itself_is_told() {
    let mut build = Build::new(12, 32);
    // Cluster 2 holds a folder, and the folder holds itself under another
    // name, which `.` and `..` would not be read as.
    let mut records = record(b".          ", 0x10, 0, 2, 0);
    records.extend(record(b"..         ", 0x10, 0, 0, 0));
    records.extend(record(b"AGAIN      ", 0x10, 0, 2, 0));
    build.put(&records, &[2]);
    build.root = record(b"SUB        ", 0x10, 0, 2, 0);
    let image = build.image();
    let fat = Fat::open(&image).unwrap();
    let mut walk = fat.walk().unwrap();
    // SUB comes out, and then the folder inside it that is SUB again.
    assert_eq!(walk.next(&fat).unwrap().unwrap().0, "SUB");
    assert!(matches!(walk.next(&fat), Err(Error::Chain { at: 2 })));
}

#[test]
fn exfat_is_told_from_fat() {
    let mut boot = vec![0u8; 1 << 20];
    boot[..3].copy_from_slice(&[0xEB, 0x76, 0x90]);
    boot[3..11].copy_from_slice(b"EXFAT   ");
    boot[510..512].copy_from_slice(&[0x55, 0xAA]);
    assert!(matches!(Fat::open(&boot), Err(Error::ExFat)));
}

#[test]
fn what_is_not_a_fat_file_system_is_told_from_one() {
    assert!(matches!(
        Fat::open(&vec![0u8; 1 << 20]),
        Err(Error::Unrecognized)
    ));
    assert!(matches!(Fat::open(&Vec::new()), Err(Error::Unrecognized)));
    // The signature and nothing else: no jump where one has to be.
    let mut only = vec![0u8; 1 << 20];
    only[510..512].copy_from_slice(&[0x55, 0xAA]);
    assert!(matches!(Fat::open(&only), Err(Error::Unrecognized)));
    // NTFS, which carries the same signature and the same jump.
    let mut ntfs = only.clone();
    ntfs[..3].copy_from_slice(&[0xEB, 0x52, 0x90]);
    ntfs[3..11].copy_from_slice(b"NTFS    ");
    assert!(matches!(Fat::open(&ntfs), Err(Error::Says)));
}

/// Layouts no file system has, each of which would otherwise be read as a
/// tree of something.
#[test]
fn a_layout_the_format_does_not_have_is_refused() {
    let sound = Build::new(12, 32).image();
    assert!(Fat::open(&sound).is_ok());
    let broken = |change: &dyn Fn(&mut Vec<u8>)| {
        let mut image = sound.clone();
        change(&mut image);
        matches!(Fat::open(&image), Err(Error::Says))
    };
    assert!(
        broken(&|i| i[11..13].copy_from_slice(&600u16.to_le_bytes())),
        "a sector of no such size"
    );
    assert!(broken(&|i| i[13] = 0), "a cluster of no sectors");
    assert!(
        broken(&|i| i[13] = 3),
        "a cluster that is not a power of two"
    );
    assert!(
        broken(&|i| i[13] = 255),
        "a cluster of more sectors than one has"
    );
    assert!(
        broken(&|i| i[14..16].copy_from_slice(&0u16.to_le_bytes())),
        "no room before the table"
    );
    assert!(broken(&|i| i[16] = 0), "no table at all");
    assert!(
        broken(&|i| i[17..19].copy_from_slice(&0u16.to_le_bytes())),
        "no root directory"
    );
    assert!(
        broken(&|i| i[22..24].copy_from_slice(&0u16.to_le_bytes())),
        "a table of no sectors"
    );
    assert!(
        broken(&|i| i[19..21].copy_from_slice(&u16::MAX.to_le_bytes())),
        "longer than the disk"
    );
    assert!(
        broken(&|i| i[19..21].copy_from_slice(&20u16.to_le_bytes())),
        "no clusters left over"
    );
}

/// A file system whose records say a longer file than its chain holds: what
/// is not in the file system is not answered as zeroes.
#[test]
fn a_file_longer_than_its_chain_is_told() {
    let mut build = Build::new(12, 32);
    let text = b"short\n".to_vec();
    let at = build.put(&text, &[2]);
    build.root = record(b"LONG    BIN", 0x20, 0, at, 4096);
    let image = build.image();
    let fat = Fat::open(&image).unwrap();
    let entry = fat.lookup_path("LONG.BIN").unwrap().unwrap();
    let mut data = Vec::new();
    let read = fat.file(&entry).unwrap().read_to_end(&mut data);
    assert!(read.is_err(), "the chain ends before the file does");
}

/// Reads of every size and at every place, against the bytes that went in.
#[test]
fn a_file_reads_the_same_in_pieces_of_any_size() {
    use std::io::{Seek, SeekFrom};

    let mut build = Build::new(12, 64);
    let text = pattern(5000, 9);
    // Clusters that follow one another, and clusters that do not: a read
    // across the first is one read of the disk, and across the second two.
    let at = build.put(&text, &[2, 3, 4, 9, 10, 20, 21, 22, 23, 24]);
    build.root = record(b"PIECES  BIN", 0x20, 0, at, text.len() as u32);
    let image = build.image();
    let fat = Fat::open(&image).unwrap();
    let entry = fat.lookup_path("PIECES.BIN").unwrap().unwrap();
    for piece in [1usize, 7, 511, 512, 513, 1024, 5000, 8192] {
        let mut file = fat.file(&entry).unwrap();
        let mut data = Vec::new();
        let mut buf = vec![0u8; piece];
        loop {
            let read = file.read(&mut buf).unwrap();
            if read == 0 {
                break;
            }
            data.extend_from_slice(&buf[..read]);
        }
        assert_eq!(data, text, "in pieces of {piece}");
    }
    // Seeking: from the start, from where it is, and from the end.
    let mut file = fat.file(&entry).unwrap();
    assert_eq!(file.len(), text.len() as u64);
    file.seek(SeekFrom::Start(4000)).unwrap();
    let mut rest = Vec::new();
    file.read_to_end(&mut rest).unwrap();
    assert_eq!(rest, text[4000..]);
    file.seek(SeekFrom::End(-10)).unwrap();
    let mut end = Vec::new();
    file.read_to_end(&mut end).unwrap();
    assert_eq!(end, text[text.len() - 10..]);
    assert!(file.seek(SeekFrom::Current(-1_000_000)).is_err());
}

/// What a reader of a disk image gets: the partitions of a card, and the
/// file system in one of them, which is the layering these two modules are
/// for.
#[test]
fn a_file_system_in_a_partition_of_a_card_is_read_through_it() {
    let (fs, want) = by_hand(16);
    // A card of one partition, where the file system begins at sector 2048
    // as every tool writes it.
    let start = 2048u32;
    let sectors = (fs.len() / 512) as u32;
    let mut card = vec![0u8; (start as usize + sectors as usize) * 512];
    card[510..512].copy_from_slice(&[0x55, 0xAA]);
    let entry = 446;
    // Type 0x0E: FAT16 as a system reading the table through the BIOS sees
    // it, which is the type `sfdisk` writes for one.
    card[entry + 4] = 0x0E;
    card[entry + 8..entry + 12].copy_from_slice(&start.to_le_bytes());
    card[entry + 12..entry + 16].copy_from_slice(&sectors.to_le_bytes());
    let at = start as usize * 512;
    card[at..at + fs.len()].copy_from_slice(&fs);

    let found = partitions(&card).unwrap().unwrap();
    assert_eq!(found.table, Table::Mbr);
    assert_eq!(found.partitions[0].kind.says(), Some("FAT16"));
    let part = Part::new(&card, found.partitions[0].at, found.partitions[0].size);
    let fat = Fat::open(&part).unwrap();
    assert_eq!(fat.kind(), Kind::Fat16);
    assert_eq!(what_it_holds(&fat), want);
}

/// A FAT32 whose root directory is longer than the start of it that is read
/// to find the label. Finding the label must not mean reading the whole
/// directory: it once did, and a root of more than 32 KiB — which is a few
/// hundred files — made opening the file system fail altogether.
#[test]
fn a_root_directory_longer_than_the_search_for_the_label_opens_all_the_same() {
    let mut build = Build::new(32, 300);
    let mut records = record(b"BY HAND    ", 0x08, 0, 0, 0);
    // 1200 records of 32 bytes is 37.5 KiB, over the 32 KiB that is read.
    for i in 0..1200u32 {
        let mut name = *b"F0000   TXT";
        for (at, digit) in format!("{i:04}").bytes().enumerate() {
            name[1 + at] = digit;
        }
        records.extend(record(&name, 0x20, 0, 0, 0));
    }
    let clusters: Vec<u32> = (2..2 + (records.len() as u32).div_ceil(512)).collect();
    assert!(
        clusters.len() > 64,
        "more clusters than the label is read in"
    );
    build.put(&records, &clusters);
    let image = build.image();
    sound("a long root", &image);
    let fat = Fat::open(&image).unwrap();
    assert_eq!(fat.label(), Some("BY HAND"));
    assert_eq!(fat.read_root().unwrap().len(), 1200);
    assert!(fat.lookup_path("F1199.TXT").unwrap().is_some());
}

/// Every entry a directory holds, as `read_dir` gives them, which is what
/// `walk` is built on.
#[test]
fn a_directory_gives_its_entries_in_the_order_it_holds_them() {
    let (image, _) = by_hand(12);
    let fat = Fat::open(&image).unwrap();
    let root = fat.read_root().unwrap();
    let names: Vec<&str> = root.iter().map(|e| e.name.as_str()).collect();
    assert_eq!(
        names,
        [
            "README.TXT",
            "lower.txt",
            "a long name of more than thirteen characters.txt",
            "tên dài.txt",
            "EMPTY.DAT",
            "SUB",
        ]
    );
    let folder: Entry = fat.lookup_path("SUB").unwrap().unwrap();
    let inside = fat.read_dir(&folder).unwrap();
    assert_eq!(inside.len(), 1, ". and .. are not entries");
    assert_eq!(inside[0].name, "INSIDE.TXT");
}
