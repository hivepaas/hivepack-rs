//! File systems built byte by byte, for the tests that read one and the
//! tests that extract one.
//!
//! The numbers are the ones `mkfs.fat` writes, so that `fsck.fat` has
//! nothing to say about them — which `tests/fat.rs` asserts over every
//! image this builds, and is what makes it worth building on.

#![allow(dead_code, clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeMap;

/// Bytes that are the same every run and not all alike.
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

// --- File systems built byte by byte -------------------------------------

/// What a file system built here is made of. The numbers are the ones
/// `mkfs.fat` writes, so that `fsck.fat` has nothing to say about them.
pub struct Build {
    pub bits: u8,
    pub sector: u32,
    pub per_cluster: u32,
    pub clusters: u32,
    pub root_entries: u32,
    pub reserved: u32,
    pub label: [u8; 11],
    /// One entry for each cluster, the two the format keeps included.
    pub fat: Vec<u32>,
    /// The data area, as long as there are clusters.
    pub data: Vec<u8>,
    /// The records of the root directory.
    pub root: Vec<u8>,
    /// Which cluster the root directory is in, for FAT32.
    pub root_cluster: u32,
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
    pub fn new(bits: u8, clusters: u32) -> Build {
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
    pub fn end(&self) -> u32 {
        match self.bits {
            12 => 0x0FFF,
            16 => 0xFFFF,
            _ => 0x0FFF_FFFF,
        }
    }

    /// How many bytes a cluster is.
    pub fn cluster(&self) -> usize {
        (self.sector * self.per_cluster) as usize
    }

    /// Puts `bytes` in the clusters `at`, chained in the order they are
    /// given, and answers the first of them.
    pub fn put(&mut self, bytes: &[u8], at: &[u32]) -> u32 {
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
    pub fn image(&self) -> Vec<u8> {
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
pub fn record(name: &[u8; 11], attributes: u8, nt: u8, first: u32, size: u32) -> Vec<u8> {
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
pub fn checksum(short: &[u8; 11]) -> u8 {
    short.iter().fold(0u8, |sum, byte| {
        ((sum & 1) << 7).wrapping_add(sum >> 1).wrapping_add(*byte)
    })
}

/// The records of a long name, in the order a file system holds them: the
/// last piece first, each with the checksum of the 8.3 name it belongs to.
pub fn long(name: &str, sum: u8) -> Vec<u8> {
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
pub fn by_hand(bits: u8) -> (Vec<u8>, BTreeMap<String, Option<Vec<u8>>>) {
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
