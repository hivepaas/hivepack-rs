//! Reading disk images in safe Rust: the disk a container holds, and the
//! partitions its table names.
//!
//! A disk image is not a file system but a block device kept in a file.
//! [`Disk`] is that device — how long it is, and reads wherever asked — and
//! [`partitions`] reads the table at its start: a master boot record, or a
//! GUID partition table. [`Part`] is one partition as a disk of its own,
//! which is what the file system in it is read from.
//!
//! A raw image (`.img`, `.bin`, a `dd` of a card) is a disk as it is, and a
//! `std::fs::File` is one. A container keeps a disk in less room than it is
//! long, and presents one, so the partitions of any of them are read as a
//! disk's are: [`Vhd`] for a VHD image (`.vhd`, QEMU's `vpc`), [`Qcow2`] for
//! QEMU's own, compressed clusters and all, [`Vhdx`] for the one Hyper-V and
//! WSL2 write, which alone says what a sector is on the disk it holds, and
//! [`Vmdk`] for VMware's, which is one file or a descriptor naming several.
//! No file system a partition holds is read yet.
//!
//! Nothing in this module is a port. A master boot record's layout is the
//! one every system has agreed on since MS-DOS, and a GUID partition
//! table's is the UEFI specification's (2.10, §5.3). How it is checked is
//! in the repository: `docs/image.md`.
//!
//! ```no_run
//! let image = std::fs::File::open("card.img")?;
//! if let Some(found) = hivepack::image::partitions(&image)? {
//!     for part in &found.partitions {
//!         println!(
//!             "{} {} bytes, {}",
//!             part.number,
//!             part.size,
//!             part.kind.says().unwrap_or("of a kind not in the list")
//!         );
//!     }
//! }
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

#![forbid(unsafe_code)]

mod crc32c;
mod disk;
mod error;
mod gpt;
mod mbr;
mod partition;
mod qcow2;
mod vhd;
mod vhdx;
mod vmdk;

pub use disk::{Disk, Part};
pub use error::{Error, Unsupported};
pub use partition::{Kind, Partition, Table};
pub use qcow2::Qcow2;
pub use vhd::Vhd;
pub use vhdx::Vhdx;
pub use vmdk::Vmdk;

/// The sector sizes a table's numbers are counted in: what every disk has
/// had, and what a disk that gave up 512-byte sectors has.
const SECTORS: [u64; 2] = [512, 4096];

/// What was found on the disk: which table it was, what a sector is on it,
/// and the partitions in the order the table holds them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Found {
    pub table: Table,
    /// How many bytes a sector is, which the table's numbers are counted
    /// in: told by where a GUID partition table's header was found, and
    /// taken to be 512 for a master boot record unless its own numbers
    /// only fit a larger one.
    pub sector: u64,
    pub partitions: Vec<Partition>,
}

/// The partitions of `disk`, or none where it has no table at all: a disk
/// holding one file system and nothing else has none, and so has a file
/// that is not a disk image.
///
/// A GUID partition table is read first, as the master boot record left in
/// front of one says to, in whichever sector size its header is found at.
/// Where a table's own CRC-32 fails, the copy at the disk's end is read
/// instead.
///
/// A master boot record is read in 512-byte sectors, which is what its
/// numbers are counted in on every disk that has ever been sold with one.
/// Nothing in the record says what a sector is, and its numbers cannot
/// tell: counted in a smaller sector they come out smaller, so they fit the
/// disk either way and only point at the wrong place. A disk whose sectors
/// are its own, and whose size is known from somewhere else — the container
/// holding it, which VHDX records and QCOW2 does not — is read by
/// [`partitions_in`].
pub fn partitions<D: Disk>(disk: &D) -> Result<Option<Found>, Error> {
    let whole = disk.size()?;
    if whole == 0 {
        return Ok(None);
    }
    for sector in SECTORS {
        if let Some(found) = gpt_in(disk, sector, whole)? {
            return Ok(Some(found));
        }
    }
    let mut first = vec![0u8; 512];
    if disk.read_at(0, &mut first)? < first.len() || !mbr::signed(&first) {
        return Ok(None);
    }
    // A disk whose GUID partition table could not be read, but which says
    // it has one, is not a disk of four empty partitions: say why.
    if mbr::protective(&first) {
        return Ok(Some(Found {
            table: Table::Gpt,
            sector: SECTORS[0],
            partitions: gpt::partitions(disk, SECTORS[0], whole)?,
        }));
    }
    Ok(Some(Found {
        table: Table::Mbr,
        sector: SECTORS[0],
        partitions: mbr::partitions(disk, &first, SECTORS[0], whole)?,
    }))
}

/// The partitions of `disk`, whose sectors are `sector` bytes: for a disk
/// whose own sector size is known from somewhere else, which is the only
/// place it can be known from for a master boot record.
///
/// `sector` must be a power of two of at least 512, as every disk's is.
pub fn partitions_in<D: Disk>(disk: &D, sector: u64) -> Result<Option<Found>, Error> {
    if sector < 512 || !sector.is_power_of_two() {
        return Err(Error::SectorSize { sector });
    }
    let whole = disk.size()?;
    if whole == 0 {
        return Ok(None);
    }
    if let Some(found) = gpt_in(disk, sector, whole)? {
        return Ok(Some(found));
    }
    let mut first = vec![0u8; 512];
    if disk.read_at(0, &mut first)? < first.len() || !mbr::signed(&first) {
        return Ok(None);
    }
    if mbr::protective(&first) {
        return Ok(Some(Found {
            table: Table::Gpt,
            sector,
            partitions: gpt::partitions(disk, sector, whole)?,
        }));
    }
    Ok(Some(Found {
        table: Table::Mbr,
        sector,
        partitions: mbr::partitions(disk, &first, sector, whole)?,
    }))
}

/// A GUID partition table, where its header is in the second sector of
/// `sector` bytes: the signature is looked for there before anything is
/// checked, so that a disk with no table costs one read.
fn gpt_in<D: Disk>(disk: &D, sector: u64, whole: u64) -> Result<Option<Found>, Error> {
    if whole <= sector {
        return Ok(None);
    }
    let mut signature = [0u8; 8];
    if disk.read_at(sector, &mut signature)? < signature.len() || &signature != gpt::SIGNATURE {
        return Ok(None);
    }
    Ok(Some(Found {
        table: Table::Gpt,
        sector,
        partitions: gpt::partitions(disk, sector, whole)?,
    }))
}
