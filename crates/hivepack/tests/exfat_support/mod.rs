//! Building exFAT volumes for the tests that read one and the tests that
//! extract one.
//!
//! Two ways, because neither is enough on its own. `Volume` has
//! `mkfs.exfat` write a real one and puts files in it here — nothing can
//! mount exFAT without root — and `fsck.exfat` is then run over the
//! result, so what hivepack reads is a volume the format's own tool calls
//! clean. `by_hand` builds one byte by byte, so the reader is checked
//! where no tool is installed, and so that a volume saying something no
//! tool would write can be built at all.
//!
//! Where `HIVEPACK_EXFAT_REQUIRED` holds a value, a missing tool is a
//! failure rather than a reason: CI gives it one on the job that installs
//! exfatprogs. Without that, a test that found no tools and a test that
//! read a volume both pass, and `cargo test` hides the printed reason for
//! a test that passes, so the suite could say nothing and look the same.
//! **An empty value is not a value**: a workflow that sets the variable
//! for every system and fills it in for one leaves the others holding an
//! empty string, which is still set as far as the environment goes.

#![allow(dead_code, clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Command;

use hivepack::exfat::Exfat;

/// A folder in the system's temporary one, removed when dropped.
pub struct Scratch(pub PathBuf);

impl Scratch {
    pub fn new(what: &str) -> Scratch {
        let path =
            std::env::temp_dir().join(format!("hivepack-exfat-{}-{what}", std::process::id()));
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

/// Whether a missing tool is to fail the test rather than be said: see
/// this module's own note.
pub fn required() -> bool {
    std::env::var("HIVEPACK_EXFAT_REQUIRED").is_ok_and(|v| !v.is_empty())
}

/// Says `why` a test is not checking what it would, or fails where the
/// tools are required.
pub fn say_or_fail(why: &str) {
    assert!(!required(), "{why}");
    eprintln!("{why}");
}

/// A tool, if it is installed **and** can be run: a process cannot be
/// started everywhere these tests run — CI's 32-bit container answers
/// `ENOSYS` to `spawn` — so a test that needs one says so and passes rather
/// than failing for the want of it. The volumes built by hand are what
/// check the reader there.
pub fn tool(name: &str) -> Option<PathBuf> {
    let path = ["/usr/sbin", "/usr/bin", "/sbin", "/bin", "/usr/local/sbin"]
        .into_iter()
        .map(|at| PathBuf::from(at).join(name))
        .find(|p| p.exists())?;
    Command::new(&path).arg("-V").output().ok()?;
    Some(path)
}

/// Bytes that are the same every run, and not all alike.
pub fn pattern(len: usize, seed: u64) -> Vec<u8> {
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

pub const ENTRY: usize = 32;
pub const FILE: u8 = 0x85;
pub const STREAM: u8 = 0xC0;
pub const NAME_ENTRY: u8 = 0xC1;
pub const BITMAP: u8 = 0x81;
pub const UPCASE: u8 = 0x82;
pub const PER_NAME: usize = 15;

/// A volume held in memory: what `mkfs.exfat` wrote, and where everything
/// in it is, so that files can be put in by hand.
pub struct Volume {
    pub bytes: Vec<u8>,
    pub sector: u64,
    pub cluster: u64,
    pub fat_at: u64,
    pub heap_at: u64,
    pub clusters: u32,
    pub root: u32,
    /// Where the allocation bitmap is, and how long: every cluster given
    /// out has its bit set here, and `fsck.exfat` checks that.
    pub bitmap_at: u64,
    pub bitmap_len: u64,
    /// The volume's own upcase table, which says how a name is folded
    /// before it is hashed. The hash is in every stream entry, and
    /// `fsck.exfat` checks it, so a test that writes names has to fold
    /// them the way the volume does.
    pub upcase: Vec<u16>,
    /// The next cluster not given out yet.
    pub next: u32,
}

pub fn le32(of: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(of[at..at + 4].try_into().unwrap())
}

pub fn le64(of: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(of[at..at + 8].try_into().unwrap())
}

impl Volume {
    /// A volume `mkfs.exfat` wrote, of `size` bytes, read into memory.
    pub fn new(s: &Scratch, size: u64, options: &[&str]) -> Option<Volume> {
        let mkfs = tool("mkfs.exfat")?;
        let path = s.0.join("volume.img");
        std::fs::write(&path, vec![0u8; size as usize]).unwrap();
        let out = Command::new(&mkfs).args(options).arg(&path).output().ok()?;
        if !out.status.success() {
            say_or_fail(&format!(
                "mkfs.exfat wrote no volume: {}",
                String::from_utf8_lossy(&out.stderr)
            ));
            return None;
        }
        let bytes = std::fs::read(&path).unwrap();
        let sector = 1u64 << bytes[108];
        let cluster = sector << bytes[109];
        let fat_at = u64::from(le32(&bytes, 80)) * sector;
        let heap_at = u64::from(le32(&bytes, 88)) * sector;
        let clusters = le32(&bytes, 92);
        let root = le32(&bytes, 96);
        let mut volume = Volume {
            bytes,
            sector,
            cluster,
            fat_at,
            heap_at,
            clusters,
            root,
            bitmap_at: 0,
            bitmap_len: 0,
            upcase: Vec::new(),
            next: 0,
        };
        // The bitmap and the upcase table are entries of the root
        // directory, as the format puts them.
        let root_at = volume.cluster_at(root);
        let root_bytes =
            volume.bytes[root_at as usize..(root_at + volume.cluster) as usize].to_vec();
        for entry in root_bytes.as_chunks::<ENTRY>().0 {
            match entry[0] {
                BITMAP => {
                    volume.bitmap_at = volume.cluster_at(le32(entry, 20));
                    volume.bitmap_len = le64(entry, 24);
                }
                UPCASE => {
                    let at = volume.cluster_at(le32(entry, 20));
                    let len = le64(entry, 24) as usize;
                    volume.upcase =
                        Volume::upcase_table(&volume.bytes[at as usize..at as usize + len]);
                }
                _ => {}
            }
        }
        assert!(volume.bitmap_len > 0, "no allocation bitmap in the root");
        assert!(!volume.upcase.is_empty(), "no upcase table in the root");
        // The first cluster nothing has been given: the bitmap says.
        volume.next = (0..volume.clusters)
            .find(|i| !volume.is_used(i + 2))
            .map(|i| i + 2)
            .expect("a volume with no free cluster");
        Some(volume)
    }

    /// The upcase table as a map from character to character. The table
    /// may be written in short: a `0xFFFF` entry means the next number is
    /// how many characters follow that are their own uppercase.
    fn upcase_table(raw: &[u8]) -> Vec<u16> {
        let mut table = Vec::new();
        let mut i = 0;
        let values: Vec<u16> = raw
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| u16::from_le_bytes(*pair))
            .collect();
        while i < values.len() {
            if values[i] == 0xFFFF && i + 1 < values.len() {
                let same = values[i + 1];
                for _ in 0..same {
                    let next = table.len() as u16;
                    table.push(next);
                }
                i += 2;
            } else {
                table.push(values[i]);
                i += 1;
            }
        }
        table
    }

    pub fn cluster_at(&self, cluster: u32) -> u64 {
        self.heap_at + u64::from(cluster - 2) * self.cluster
    }

    fn is_used(&self, cluster: u32) -> bool {
        let bit = u64::from(cluster - 2);
        let byte = self.bytes[(self.bitmap_at + bit / 8) as usize];
        byte & (1 << (bit % 8)) != 0
    }

    fn take(&mut self, cluster: u32) {
        let bit = u64::from(cluster - 2);
        let at = (self.bitmap_at + bit / 8) as usize;
        self.bytes[at] |= 1 << (bit % 8);
    }

    /// `name` folded as the volume's table folds it, which is what the hash
    /// in a stream entry is of.
    pub fn upcased(&self, name: &str) -> Vec<u16> {
        name.encode_utf16()
            .map(|unit| self.upcase.get(usize::from(unit)).copied().unwrap_or(unit))
            .collect()
    }

    /// The hash of a name, which `fsck.exfat` checks: every byte of the
    /// folded name, each added to the sum after it is turned about by one
    /// bit.
    pub fn name_hash(&self, name: &str) -> u16 {
        let mut sum = 0u16;
        for unit in self.upcased(name) {
            for byte in unit.to_le_bytes() {
                sum = sum.rotate_right(1).wrapping_add(u16::from(byte));
            }
        }
        sum
    }

    /// A set of entries for one file or directory, with its checksum and
    /// its name hash put in.
    pub fn a_set(
        &self,
        name: &str,
        size: u64,
        valid: u64,
        first: u32,
        dir: bool,
        run: bool,
    ) -> Vec<u8> {
        let units: Vec<u16> = name.encode_utf16().collect();
        let names = units.len().div_ceil(PER_NAME);
        let mut set = vec![0u8; ENTRY * (2 + names)];
        set[0] = FILE;
        set[1] = (1 + names) as u8;
        let attributes: u16 = if dir { 0x10 } else { 0x20 };
        set[4..6].copy_from_slice(&attributes.to_le_bytes());
        // 2026-11-19 12:00:00, the same in every entry, and marked as UTC.
        let stamp = (((2026u32 - 1980) << 9 | 11 << 5 | 19) << 16) | (12 << 11);
        for at in [8, 12, 16] {
            set[at..at + 4].copy_from_slice(&stamp.to_le_bytes());
        }
        for at in [22, 23, 24] {
            set[at] = 0x80;
        }
        set[ENTRY] = STREAM;
        // The second flag says the data is one run with nothing in the
        // table; the first says it was given room at all.
        set[ENTRY + 1] = if run { 0x03 } else { 0x01 };
        set[ENTRY + 3] = units.len() as u8;
        set[ENTRY + 4..ENTRY + 6].copy_from_slice(&self.name_hash(name).to_le_bytes());
        set[ENTRY + 8..ENTRY + 16].copy_from_slice(&valid.to_le_bytes());
        set[ENTRY + 20..ENTRY + 24].copy_from_slice(&first.to_le_bytes());
        set[ENTRY + 24..ENTRY + 32].copy_from_slice(&size.to_le_bytes());
        for (i, chunk) in units.chunks(PER_NAME).enumerate() {
            let at = ENTRY * (2 + i);
            set[at] = NAME_ENTRY;
            for (j, unit) in chunk.iter().enumerate() {
                set[at + 2 + j * 2..at + 4 + j * 2].copy_from_slice(&unit.to_le_bytes());
            }
        }
        let mut sum = 0u16;
        for (i, byte) in set.iter().enumerate() {
            if i == 2 || i == 3 {
                continue;
            }
            sum = sum.rotate_right(1).wrapping_add(u16::from(*byte));
        }
        set[2..4].copy_from_slice(&sum.to_le_bytes());
        set
    }

    /// Gives out `how_many` clusters, marking the bitmap, and chains them
    /// in the table where they are not one run.
    pub fn give(&mut self, how_many: u64, run: bool) -> Vec<u32> {
        let mut given = Vec::new();
        for _ in 0..how_many {
            let mut cluster = self.next;
            if !run {
                // One cluster of space between each, so that the chain is
                // not a run by accident and the table is what finds it.
                cluster += 1;
            }
            while self.is_used(cluster) {
                cluster += 1;
            }
            self.take(cluster);
            given.push(cluster);
            self.next = cluster + 1;
        }
        if !run {
            for pair in given.windows(2) {
                self.put_fat(pair[0], pair[1]);
            }
            if let Some(last) = given.last() {
                self.put_fat(*last, 0xFFFF_FFFF);
            }
        }
        // A run says so in its own entry, and then the table holds nothing
        // for it: it is left as mkfs wrote it.
        given
    }

    pub fn put_fat(&mut self, cluster: u32, value: u32) {
        let at = (self.fat_at + u64::from(cluster) * 4) as usize;
        self.bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
    }

    /// Writes `data` into the clusters, and returns where it starts.
    pub fn put_data(&mut self, data: &[u8], clusters: &[u32]) {
        for (i, cluster) in clusters.iter().enumerate() {
            let at = self.cluster_at(*cluster) as usize;
            let from = i * self.cluster as usize;
            let take = (data.len() - from).min(self.cluster as usize);
            self.bytes[at..at + take].copy_from_slice(&data[from..from + take]);
        }
    }

    /// Adds entries to the end of a directory's own cluster, which is
    /// where its unused entries are.
    pub fn add_entries(&mut self, dir_cluster: u32, sets: &[Vec<u8>]) {
        let at = self.cluster_at(dir_cluster) as usize;
        let room = self.cluster as usize;
        let free = self.bytes[at..at + room]
            .as_chunks::<ENTRY>()
            .0
            .iter()
            .position(|entry| entry[0] == 0)
            .expect("a directory with no room left");
        let mut put = at + free * ENTRY;
        for set in sets {
            assert!(put + set.len() <= at + room, "the directory filled up");
            self.bytes[put..put + set.len()].copy_from_slice(set);
            put += set.len();
        }
    }

    /// A file of `data`, by its name, in the root directory.
    pub fn add_file(&mut self, name: &str, data: &[u8], run: bool) {
        let clusters = self.give((data.len() as u64).div_ceil(self.cluster).max(1), run);
        self.put_data(data, &clusters);
        let set = self.a_set(
            name,
            data.len() as u64,
            data.len() as u64,
            clusters[0],
            false,
            run,
        );
        let root = self.root;
        self.add_entries(root, &[set]);
    }

    /// A directory in the root, holding one file of `data`.
    pub fn add_dir_with_file(&mut self, dir: &str, name: &str, data: &[u8]) {
        let inside = self.give(1, true)[0];
        let data_clusters = self.give((data.len() as u64).div_ceil(self.cluster).max(1), true);
        self.put_data(data, &data_clusters);
        let file = self.a_set(
            name,
            data.len() as u64,
            data.len() as u64,
            data_clusters[0],
            false,
            true,
        );
        self.add_entries(inside, &[file]);
        let set = self.a_set(dir, self.cluster, self.cluster, inside, true, true);
        let root = self.root;
        self.add_entries(root, &[set]);
    }

    /// Writes the volume out, puts the boot checksum right, and hands back
    /// the path.
    pub fn write(&mut self, s: &Scratch, name: &str) -> PathBuf {
        // Nothing here changes the boot region, so its checksum is still
        // the one mkfs wrote; this is here so that a test that does change
        // it can put it right.
        let path = s.0.join(name);
        std::fs::write(&path, &self.bytes).unwrap();
        path
    }

    /// What `fsck.exfat` says about it: nothing to report, or why.
    ///
    /// Where it is not installed this says so out loud rather than
    /// quietly: a test whose oracle is missing is a test that passes for
    /// the wrong reason.
    pub fn fsck(path: &Path) -> Result<(), String> {
        let Some(fsck) = tool("fsck.exfat") else {
            say_or_fail("fsck.exfat cannot be run here: the volume is read but not checked by it");
            return Ok(());
        };
        let out = Command::new(&fsck).arg("-n").arg(path).output().unwrap();
        if out.status.success() {
            Ok(())
        } else {
            Err(format!(
                "fsck.exfat is not happy with the volume:\n{}{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            ))
        }
    }
}

/// Every byte of a file in the volume, by its path.
pub fn whole(exfat: &Exfat<std::fs::File>, path: &str) -> Vec<u8> {
    let entry = exfat
        .lookup_path(path)
        .unwrap()
        .unwrap_or_else(|| panic!("{path} is not in the volume"));
    let mut data = Vec::new();
    exfat.file(&entry).unwrap().read_to_end(&mut data).unwrap();
    data
}

/// Volumes built byte by byte: what checks the reader where no tool is
/// installed, and the only way to build a volume that says something no
/// tool would write.
pub mod by_hand {
    use super::{ENTRY, FILE, NAME_ENTRY, PER_NAME, STREAM};

    pub const SECTOR: usize = 512;
    pub const CLUSTER_SHIFT: u8 = 3;
    pub const CLUSTER: usize = SECTOR << CLUSTER_SHIFT;
    /// Where the table and the heap go: after both boot regions, and the
    /// table rounded up to a sector.
    pub const FAT_SECTOR: u64 = 24;
    pub const FAT_SECTORS: u64 = 1;
    pub const HEAP_SECTOR: u64 = 32;
    pub const CLUSTERS: u32 = 16;

    /// A volume of [`CLUSTERS`] clusters, its root at cluster 2, with
    /// `change` run over the boot sector before its checksum is worked
    /// out.
    pub fn a_volume(change: impl FnOnce(&mut [u8])) -> Vec<u8> {
        let volume_sectors = HEAP_SECTOR + u64::from(CLUSTERS) * (1 << CLUSTER_SHIFT);
        let mut bytes = vec![0u8; volume_sectors as usize * SECTOR];
        let boot = &mut bytes[..SECTOR];
        boot[0..3].copy_from_slice(&[0xEB, 0x76, 0x90]);
        boot[3..11].copy_from_slice(b"EXFAT   ");
        boot[72..80].copy_from_slice(&volume_sectors.to_le_bytes());
        boot[80..84].copy_from_slice(&(FAT_SECTOR as u32).to_le_bytes());
        boot[84..88].copy_from_slice(&(FAT_SECTORS as u32).to_le_bytes());
        boot[88..92].copy_from_slice(&(HEAP_SECTOR as u32).to_le_bytes());
        boot[92..96].copy_from_slice(&CLUSTERS.to_le_bytes());
        boot[96..100].copy_from_slice(&2u32.to_le_bytes());
        boot[100..104].copy_from_slice(&0x1234_5678u32.to_le_bytes());
        boot[104..106].copy_from_slice(&0x0100u16.to_le_bytes());
        boot[108] = 9;
        boot[109] = CLUSTER_SHIFT;
        boot[110] = 1;
        boot[510..512].copy_from_slice(&[0x55, 0xAA]);
        change(boot);
        // The table's own first two entries, which stand for the numbers
        // no cluster has, and the root's chain: one cluster, and the end.
        put_fat(&mut bytes, 0, 0xFFFF_FFF8);
        put_fat(&mut bytes, 1, 0xFFFF_FFFF);
        put_fat(&mut bytes, 2, 0xFFFF_FFFF);
        put_checksum(&mut bytes, 0);
        bytes
    }

    /// The checksum of the first eleven sectors of the region at `at`,
    /// written into the sector after them as the format keeps it.
    pub fn put_checksum(bytes: &mut [u8], at: usize) {
        let mut sum = 0u32;
        for i in 0..11 * SECTOR {
            if [106, 107, 112].contains(&i) {
                continue;
            }
            sum = sum.rotate_right(1).wrapping_add(u32::from(bytes[at + i]));
        }
        for four in bytes[at + 11 * SECTOR..at + 12 * SECTOR]
            .as_chunks_mut::<4>()
            .0
        {
            four.copy_from_slice(&sum.to_le_bytes());
        }
    }

    pub fn cluster_at(cluster: u32) -> usize {
        (HEAP_SECTOR as usize + (cluster as usize - 2) * (1 << CLUSTER_SHIFT)) * SECTOR
    }

    pub fn put_fat(bytes: &mut [u8], cluster: u32, value: u32) {
        let at = FAT_SECTOR as usize * SECTOR + cluster as usize * 4;
        bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
    }

    /// A set of entries, as `exfat::dir`'s own tests build one: no name
    /// hash, which nothing in the reader looks at.
    pub fn a_set(name: &str, size: u64, first: u32, dir: bool, run: bool) -> Vec<u8> {
        let units: Vec<u16> = name.encode_utf16().collect();
        let names = units.len().div_ceil(PER_NAME);
        let mut set = vec![0u8; ENTRY * (2 + names)];
        set[0] = FILE;
        set[1] = (1 + names) as u8;
        set[4..6].copy_from_slice(&(if dir { 0x10u16 } else { 0x20 }).to_le_bytes());
        set[ENTRY] = STREAM;
        set[ENTRY + 1] = if run { 0x03 } else { 0x01 };
        set[ENTRY + 3] = units.len() as u8;
        set[ENTRY + 8..ENTRY + 16].copy_from_slice(&size.to_le_bytes());
        set[ENTRY + 20..ENTRY + 24].copy_from_slice(&first.to_le_bytes());
        set[ENTRY + 24..ENTRY + 32].copy_from_slice(&size.to_le_bytes());
        for (i, chunk) in units.chunks(PER_NAME).enumerate() {
            let at = ENTRY * (2 + i);
            set[at] = NAME_ENTRY;
            for (j, unit) in chunk.iter().enumerate() {
                set[at + 2 + j * 2..at + 4 + j * 2].copy_from_slice(&unit.to_le_bytes());
            }
        }
        let mut sum = 0u16;
        for (i, byte) in set.iter().enumerate() {
            if i == 2 || i == 3 {
                continue;
            }
            sum = sum.rotate_right(1).wrapping_add(u16::from(*byte));
        }
        set[2..4].copy_from_slice(&sum.to_le_bytes());
        set
    }

    /// A volume holding one file of `data` in its root, cut over two
    /// clusters that are not next to each other: the table is what finds
    /// the second.
    pub fn with_a_cut_up_file(data: &[u8]) -> Vec<u8> {
        let mut bytes = a_volume(|_| {});
        // The root is cluster 2; the file is in 4 and then 6.
        let set = a_set("cut.bin", data.len() as u64, 4, false, false);
        let root = cluster_at(2);
        bytes[root..root + set.len()].copy_from_slice(&set);
        put_fat(&mut bytes, 4, 6);
        put_fat(&mut bytes, 6, 0xFFFF_FFFF);
        let first = data.len().min(CLUSTER);
        let at = cluster_at(4);
        bytes[at..at + first].copy_from_slice(&data[..first]);
        if data.len() > first {
            let at = cluster_at(6);
            bytes[at..at + data.len() - first].copy_from_slice(&data[first..]);
        }
        bytes
    }
}
