//! The boot sector: what the volume is made of, and the checksum the
//! format keeps over the region holding it.

use crate::image::Disk;

use super::error::Error;

/// What a boot sector says of itself, at the bytes the specification fixes.
const SIGNATURE_AT: usize = 3;
const SIGNATURE: &[u8; 8] = b"EXFAT   ";
/// The bytes between the signature and the fields, which the specification
/// says are zero in an exFAT volume and hold FAT's own numbers in a FAT
/// one: that is what tells the two apart, since both end with 0x55AA.
const MUST_BE_ZERO: core::ops::Range<usize> = 11..64;
const SIGNATURE_END: usize = 510;
const END: [u8; 2] = [0x55, 0xAA];

/// How long the boot sector is as the checksum reads it, how many sectors
/// the region it covers holds, and where the backup region begins.
const BOOT_SECTORS: u64 = 11;
const REGION_SECTORS: u64 = 12;
const BACKUP_AT: u64 = 12;

/// The bytes the checksum skips: the volume flags, which change as a
/// volume is mounted, and how full it is.
const SKIPPED: [usize; 3] = [106, 107, 112];

/// What a cluster may be at most, which is the shifts the format allows
/// taken together: 32 MiB.
const MOST_CLUSTER: u64 = 32 << 20;
/// How many clusters a volume may hold at most, as the specification says:
/// the two numbers that are not clusters taken off what a 32-bit number
/// counts.
const MOST_CLUSTERS: u32 = 0xFFFF_FFF5;
/// The first cluster of the heap. Clusters 0 and 1 are not clusters: the
/// numbers are kept for the table's own first two entries.
pub(crate) const FIRST_CLUSTER: u32 = 2;

/// Where things are on the volume, in bytes, and how large.
pub(crate) struct Boot {
    /// How many bytes a sector is, and a cluster.
    pub(crate) sector: u32,
    pub(crate) cluster: u32,
    /// How many clusters the heap holds, numbered from 2.
    pub(crate) clusters: u32,
    /// Where the table hivepack reads begins, and how long it is: the
    /// active one, which the volume flags name where there are two.
    pub(crate) fat_at: u64,
    pub(crate) fat_len: u64,
    /// Where the clusters begin.
    pub(crate) heap_at: u64,
    /// Which cluster the root directory begins at.
    pub(crate) root: u32,
    /// The volume's serial number, as every tool shows it.
    pub(crate) serial: u32,
    /// What the volume flags say: that it was not unmounted cleanly, and
    /// that whatever wrote it found a sector it could not use.
    pub(crate) dirty: bool,
    pub(crate) media_failure: bool,
    /// Which boot region was read: false for the one at the volume's
    /// start, true for the backup, which is read where the first fails its
    /// checksum.
    pub(crate) backup: bool,
}

impl Boot {
    /// The volume on `disk`, read from the boot region at its start, or
    /// from the backup region where that one fails the checksum the format
    /// keeps for it.
    ///
    /// The checksum is over every byte of the first eleven sectors but the
    /// three that change while a volume is mounted, and it is the only
    /// check the format itself carries at this level. A volume whose first
    /// region fails it has had its start overwritten — by a partition
    /// table written over it, most often — and the backup is what a tool
    /// repairs it from.
    pub(crate) fn read<D: Disk>(disk: &D) -> Result<Boot, Error> {
        let why = match Boot::at(disk, 0) {
            Ok(boot) => return Ok(boot),
            // Not exFAT at all, FAT, or a disk that could not be read: the
            // backup region would say the same thing.
            Err(e @ (Error::Unrecognized | Error::Fat | Error::Io(_))) => return Err(e),
            Err(e) => e,
        };
        // The backup region is at sector 12 of whatever a sector is on this
        // volume — a number that is in the region that just failed. So it is
        // looked for at each sector size the format allows, largest first,
        // and taken only where the region found there says the same size: a
        // smaller one would otherwise find the backup of a volume of larger
        // sectors somewhere inside its boot code.
        for shift in (9..=12).rev() {
            let sector = 1u64 << shift;
            if let Ok(mut boot) = Boot::at(disk, BACKUP_AT * sector)
                && u64::from(boot.sector) == sector
            {
                boot.backup = true;
                return Ok(boot);
            }
        }
        // The first region's own reason, which says more than the backup's.
        Err(why)
    }

    /// The boot region beginning at `at`, checked through.
    fn at<D: Disk>(disk: &D, at: u64) -> Result<Boot, Error> {
        let mut first = [0u8; 512];
        if disk.read_at(at, &mut first)? < first.len() {
            return Err(Error::Unrecognized);
        }
        if first[SIGNATURE_END..SIGNATURE_END + 2] != END {
            return Err(Error::Unrecognized);
        }
        if &first[SIGNATURE_AT..SIGNATURE_AT + 8] != SIGNATURE {
            return Err(Error::Unrecognized);
        }
        // A FAT volume can carry `EXFAT   ` nowhere but in its own file
        // system type, which is further on; what says a volume is exFAT is
        // that the bytes FAT keeps its numbers in are all zero.
        if first[MUST_BE_ZERO].iter().any(|b| *b != 0) {
            return Err(Error::Fat);
        }

        let sector_shift = first[108];
        let cluster_shift = first[109];
        if !(9..=12).contains(&sector_shift) {
            return Err(Error::Says);
        }
        let sector = 1u64 << sector_shift;
        if u64::from(cluster_shift) > 25 - u64::from(sector_shift) {
            return Err(Error::Says);
        }
        let cluster = sector << cluster_shift;
        if cluster > MOST_CLUSTER {
            return Err(Error::Says);
        }

        // The checksum over the region, before anything it says is used
        // for where to read next.
        checksum(disk, at, sector)?;

        let volume_sectors = le64(&first, 72);
        let fat_sector = u64::from(le32(&first, 80));
        let fat_sectors = u64::from(le32(&first, 84));
        let heap_sector = u64::from(le32(&first, 88));
        let clusters = le32(&first, 92);
        let root = le32(&first, 96);
        let serial = le32(&first, 100);
        let flags = le16(&first, 106);
        let fats = first[110];

        if !(1..=2).contains(&fats) || clusters == 0 || clusters > MOST_CLUSTERS {
            return Err(Error::Says);
        }
        // Every structure has to be on the volume, and after the boot
        // regions: the backup's own sectors are not free for a table.
        if fat_sector < REGION_SECTORS * 2 || fat_sectors == 0 {
            return Err(Error::Says);
        }
        // The table has to be long enough for every cluster, and for the
        // two entries that stand for the numbers no cluster has.
        let wanted = (u64::from(clusters) + u64::from(FIRST_CLUSTER)) * 4;
        if fat_sectors * sector < wanted {
            return Err(Error::Says);
        }
        let tables = fat_sectors * u64::from(fats);
        if fat_sector
            .checked_add(tables)
            .is_none_or(|end| end > heap_sector)
        {
            return Err(Error::Says);
        }
        // The heap has to hold the clusters it says it does, and end on the
        // volume.
        let heap_bytes = u64::from(clusters) * cluster;
        let heap_at = heap_sector * sector;
        if heap_at
            .checked_add(heap_bytes)
            .is_none_or(|end| end > volume_sectors * sector)
        {
            return Err(Error::Says);
        }
        if root < FIRST_CLUSTER || root - FIRST_CLUSTER >= clusters {
            return Err(Error::Says);
        }

        // Which table is the active one, where the volume has two: the
        // first flag says so, and TexFAT is the only thing that writes a
        // second table at all.
        let second = flags & 1 != 0;
        let active = if second && fats == 2 { 1 } else { 0 };
        Ok(Boot {
            sector: sector as u32,
            cluster: cluster as u32,
            clusters,
            fat_at: (fat_sector + fat_sectors * active) * sector,
            fat_len: fat_sectors * sector,
            heap_at,
            root,
            serial,
            dirty: flags & 2 != 0,
            media_failure: flags & 4 != 0,
            backup: false,
        })
    }

    /// Where the `cluster` cluster begins, or none where it is not a
    /// cluster of this volume.
    pub(crate) fn at_cluster(&self, cluster: u32) -> Option<u64> {
        let which = cluster.checked_sub(FIRST_CLUSTER)?;
        if which >= self.clusters {
            return None;
        }
        Some(self.heap_at + u64::from(which) * u64::from(self.cluster))
    }
}

/// Whether the boot region at `at` passes the checksum kept in the sector
/// after the eleven it covers.
///
/// The checksum is of every byte of those eleven sectors but the volume
/// flags and the byte saying how full the volume is, each byte added to the
/// sum after it is turned about by one bit. The sector holding it holds it
/// over and over, as many times as it fits; the first is read.
fn checksum<D: Disk>(disk: &D, at: u64, sector: u64) -> Result<(), Error> {
    let mut sum = 0u32;
    let mut buf = vec![0u8; sector as usize];
    for i in 0..BOOT_SECTORS {
        disk.read_exact_at(at + i * sector, &mut buf)?;
        for (j, byte) in buf.iter().enumerate() {
            let which = (i * sector) as usize + j;
            if SKIPPED.contains(&which) {
                continue;
            }
            sum = sum.rotate_right(1).wrapping_add(u32::from(*byte));
        }
    }
    let mut told = [0u8; 4];
    disk.read_exact_at(at + BOOT_SECTORS * sector, &mut told)?;
    if u32::from_le_bytes(told) == sum {
        Ok(())
    } else {
        Err(Error::Checksum)
    }
}

fn le16(of: &[u8], at: usize) -> u16 {
    of.get(at..at + 2)
        .and_then(|b| b.try_into().ok())
        .map_or(0, u16::from_le_bytes)
}

fn le32(of: &[u8], at: usize) -> u32 {
    of.get(at..at + 4)
        .and_then(|b| b.try_into().ok())
        .map_or(0, u32::from_le_bytes)
}

fn le64(of: &[u8], at: usize) -> u64 {
    of.get(at..at + 8)
        .and_then(|b| b.try_into().ok())
        .map_or(0, u64::from_le_bytes)
}
