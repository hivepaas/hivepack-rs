//! The boot sector, and what it says the file system is made of.

use crate::image::Disk;

use super::error::Error;

/// Which of the three it is, which is told by how many data clusters there
/// are and by nothing else: the numbers Microsoft's specification gives,
/// and what every tool that writes one counts with.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// Fewer than 4085 clusters: a floppy, and a card formatted as one.
    Fat12,
    /// Fewer than 65525: what a camera's card and a small partition have.
    Fat16,
    /// The rest, and what an EFI system partition is.
    Fat32,
}

impl Kind {
    /// What it is called, as a tool names it.
    pub fn says(self) -> &'static str {
        match self {
            Kind::Fat12 => "FAT12",
            Kind::Fat16 => "FAT16",
            Kind::Fat32 => "FAT32",
        }
    }
}

/// How few clusters a FAT12 file system has: the number the specification
/// counts with, and the one place a count still decides what a file system
/// is. See [`Boot::read`] for why FAT32 is not told this way.
const FAT12_MOST: u32 = 4085;

/// The sector sizes the format has.
const SECTORS: [u32; 4] = [512, 1024, 2048, 4096];

/// How many sectors a cluster may be: a power of two, and a cluster of more
/// than 32 KiB is past what the specification allows, though some tools
/// write 64 KiB. Both are read.
const MOST_PER_CLUSTER: u32 = 128;

/// How many copies of the table there may be: two in every file system any
/// tool writes, one in some an embedded system writes.
const MOST_FATS: u32 = 4;

/// What the boot sector says, of what reading the file system needs.
pub(crate) struct Boot {
    /// How many bytes a sector is, and how many a cluster.
    pub(crate) sector: u32,
    pub(crate) cluster: u32,
    /// Where the first table is, in sectors, and how long each copy is.
    pub(crate) fat_at: u32,
    pub(crate) fat_sectors: u32,
    /// Which copy of the table is read: the first, unless a FAT32 file
    /// system says the copies are not kept alike and names another.
    pub(crate) fat: u32,
    /// How many entries the root directory holds, where it is an area of
    /// its own rather than a chain: none in FAT32.
    pub(crate) root_entries: u32,
    /// Where the root directory is, in sectors, for FAT12 and FAT16; and
    /// which cluster it starts at, for FAT32.
    pub(crate) root_at: u32,
    pub(crate) root_cluster: u32,
    /// Where the data begins, in sectors, and how many clusters there are:
    /// the clusters are numbered 2 to `clusters + 1`.
    pub(crate) data_at: u32,
    pub(crate) clusters: u32,
    pub(crate) kind: Kind,
    /// The label the boot sector carries, which is not where a tool looks
    /// first: see [`super::Fat::label`].
    pub(crate) label: Option<String>,
}

impl Boot {
    /// What the boot sector of `disk` says, if it is one.
    pub(crate) fn read<D: Disk>(disk: &D) -> Result<Boot, Error> {
        let whole = disk.size()?;
        let mut first = [0u8; 512];
        if disk.read_at(0, &mut first)? < first.len() {
            return Err(Error::Unrecognized);
        }
        // The signature every boot sector ends with, and the jump every one
        // begins with: what the first byte is, is how a tool tells a boot
        // sector from a sector of something else.
        if first[510..512] != [0x55, 0xAA] {
            return Err(Error::Unrecognized);
        }
        if !matches!(first[0], 0xEB | 0xE9) {
            return Err(Error::Unrecognized);
        }
        // exFAT keeps the same signature and the same jump, says its name
        // where the one that made the file system goes, and leaves every
        // field FAT's numbers are in zero.
        if &first[3..11] == b"EXFAT   " {
            return Err(Error::ExFat);
        }
        let sector = u32::from(le16(&first, 11));
        let per_cluster = u32::from(first[13]);
        let reserved = u32::from(le16(&first, 14));
        let fats = u32::from(first[16]);
        let root_entries = u32::from(le16(&first, 17));
        let small_sectors = u32::from(le16(&first, 19));
        let small_fat = u32::from(le16(&first, 22));
        let large_sectors = le32(&first, 32);
        if !SECTORS.contains(&sector)
            || per_cluster == 0
            || !per_cluster.is_power_of_two()
            || per_cluster > MOST_PER_CLUSTER
            || reserved == 0
            || fats == 0
            || fats > MOST_FATS
        {
            return Err(Error::Says);
        }
        // Each number has a small field and a large one, and whichever is
        // not zero is the one that counts.
        let total_sectors = if small_sectors != 0 {
            small_sectors
        } else {
            large_sectors
        };
        let fat_sectors = if small_fat != 0 {
            small_fat
        } else {
            le32(&first, 36)
        };
        if total_sectors == 0 || fat_sectors == 0 {
            return Err(Error::Says);
        }
        // The file system has to be on the disk it is read from. A
        // partition is often longer than the file system in it, which is
        // not a reason to refuse one.
        if u64::from(total_sectors) * u64::from(sector) > whole {
            return Err(Error::Says);
        }
        // The root directory of FAT12 and FAT16 is an area between the
        // tables and the data, as many entries of 32 bytes as it says;
        // FAT32 has none, and keeps the root in a chain like any other.
        let root_sectors = (root_entries * 32).div_ceil(sector);
        let before = reserved
            .checked_add(fats.checked_mul(fat_sectors).ok_or(Error::Says)?)
            .and_then(|at| at.checked_add(root_sectors))
            .ok_or(Error::Says)?;
        let clusters = total_sectors
            .checked_sub(before)
            .ok_or(Error::Says)?
            .checked_div(per_cluster)
            .ok_or(Error::Says)?;
        if clusters == 0 {
            return Err(Error::Says);
        }
        // Which of the three it is. Microsoft's specification says the
        // cluster count decides, and for FAT32 that is wrong: `mkfs.fat -F
        // 32` on 32 MiB writes a file system of 64496 clusters, fewer than
        // the 65525 the rule calls FAT32, whose table is four bytes to an
        // entry all the same. So the shape of the boot sector decides
        // FAT32 — a table with no 16-bit length, and no root directory of
        // its own — which is what Linux's own reader goes by, and the
        // count decides only between FAT12 and FAT16.
        let kind = if small_fat == 0 && root_entries == 0 {
            Kind::Fat32
        } else if clusters < FAT12_MOST {
            Kind::Fat12
        } else {
            Kind::Fat16
        };
        // What the table can say, which is what there may be clusters of:
        // a file system saying more than its own table reaches is read as
        // far as the table does, as Linux reads one.
        let room = u64::from(fat_sectors) * u64::from(sector);
        let most = match kind {
            Kind::Fat12 => room * 2 / 3,
            Kind::Fat16 => room / 2,
            Kind::Fat32 => room / 4,
        };
        let clusters = clusters.min(most.saturating_sub(2).min(u64::from(u32::MAX)) as u32);
        if clusters == 0 {
            return Err(Error::Says);
        }
        // A FAT32 file system has the fields FAT12 and FAT16 have not, and
        // the two keep what says the label in different places.
        let (root_cluster, fat, label) = if kind == Kind::Fat32 {
            let flags = le16(&first, 40);
            // Where the copies of the table are not kept alike, only one
            // of them is the file system's: bit 7 says so, and the low
            // bits say which.
            let fat = if flags & 0x80 != 0 {
                u32::from(flags) & 0x0F
            } else {
                0
            };
            if fat >= fats {
                return Err(Error::Says);
            }
            let root = le32(&first, 44);
            if root < 2 || root > clusters.saturating_add(1) {
                return Err(Error::Says);
            }
            (root, fat, label_of(&first, 71))
        } else {
            if root_entries == 0 {
                return Err(Error::Says);
            }
            (0, 0, label_of(&first, 43))
        };
        Ok(Boot {
            sector,
            cluster: sector * per_cluster,
            fat_at: reserved,
            fat_sectors,
            fat,
            root_entries,
            root_at: reserved + fats * fat_sectors,
            root_cluster,
            data_at: before,
            clusters,
            kind,
            label,
        })
    }

    /// Where the `cluster` cluster's data is, in bytes, or none where it is
    /// not a cluster of this file system.
    pub(crate) fn at(&self, cluster: u32) -> Option<u64> {
        if cluster < 2 || cluster > self.clusters.saturating_add(1) {
            return None;
        }
        let sector = u64::from(self.data_at)
            + u64::from(cluster - 2) * u64::from(self.cluster / self.sector);
        Some(sector * u64::from(self.sector))
    }

    /// Where the root directory's own area is, and how long, for a file
    /// system that has one.
    pub(crate) fn root(&self) -> Option<(u64, u64)> {
        if self.kind == Kind::Fat32 {
            return None;
        }
        Some((
            u64::from(self.root_at) * u64::from(self.sector),
            u64::from(self.root_entries) * 32,
        ))
    }

    /// Where the table this reads is, in bytes.
    pub(crate) fn fat(&self) -> u64 {
        u64::from(self.fat_at + self.fat * self.fat_sectors) * u64::from(self.sector)
    }
}

/// The label of 11 bytes at `at`, as the boot sector carries it: spaces to
/// its right, and a label of nothing but spaces is none.
fn label_of(first: &[u8; 512], at: usize) -> Option<String> {
    // The field is there only where the byte before the volume's own number
    // says the fields after it were written at all.
    if first[at - 5] != 0x29 {
        return None;
    }
    let raw = &first[at..at + 11];
    let text: String = raw
        .iter()
        .map(|b| super::dir::oem(*b))
        .collect::<String>()
        .trim_end()
        .to_owned();
    if text.is_empty() { None } else { Some(text) }
}

fn le16(of: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([of[at], of[at + 1]])
}

fn le32(of: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([of[at], of[at + 1], of[at + 2], of[at + 3]])
}
